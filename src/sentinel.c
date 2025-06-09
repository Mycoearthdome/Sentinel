#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/stat.h>
#include <limits.h>
#include <signal.h>

static const char *EVIL_PROCESS_SIGNATURES[] = {"evilproc", "badproc", NULL};
static const char *EVIL_MODULE_SIGNATURES[] = {"evilmod", "badmodule", NULL};

static void check_ld_preload(void) {
    const char *env = getenv("LD_PRELOAD");
    if (env && *env) {
        syslog(LOG_WARNING, "LD_PRELOAD env: %s", env);
    }
    FILE *f = fopen("/etc/ld.so.preload", "r");
    if (f) {
        char buf[1024];
        if (fgets(buf, sizeof(buf), f)) {
            buf[strcspn(buf, "\n")] = '\0';
            if (*buf) {
                syslog(LOG_WARNING, "ld.so.preload: %s", buf);
            }
        }
        fclose(f);
    }
}

static void check_tmp_exec(void) {
    DIR *d = opendir("/proc");
    if (!d) return;
    struct dirent *de;
    char path[PATH_MAX];
    char exe[PATH_MAX];
    while ((de = readdir(d))) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        snprintf(path, sizeof(path), "/proc/%s/exe", de->d_name);
        ssize_t len = readlink(path, exe, sizeof(exe) - 1);
        if (len > 0) {
            exe[len] = '\0';
            if (!strncmp(exe, "/tmp", 4) || !strncmp(exe, "/dev", 4) || !strncmp(exe, "/run", 4)) {
                syslog(LOG_WARNING, "Executable from tmp: PID %s -> %s", de->d_name, exe);
            }
        }
    }
    closedir(d);
}

static int read_lsmod(char mods[][64], int max) {
    FILE *p = popen("lsmod", "r");
    if (!p) return -1;
    char line[256];
    int n = 0;
    fgets(line, sizeof(line), p); /* header */
    while (n < max && fgets(line, sizeof(line), p)) {
        sscanf(line, "%63s", mods[n]);
        n++;
    }
    pclose(p);
    return n;
}

static void check_hidden_modules(void) {
    char listed[512][64];
    int count = read_lsmod(listed, 512);
    if (count < 0) {
        syslog(LOG_ERR, "lsmod error");
        return;
    }
    FILE *f = fopen("/proc/modules", "r");
    if (!f) {
        syslog(LOG_ERR, "/proc/modules error");
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char mod[64];
        sscanf(line, "%63s", mod);
        int i;
        for (i = 0; i < count; i++) {
            if (strcmp(mod, listed[i]) == 0)
                break;
        }
        if (i == count) {
            syslog(LOG_WARNING, "Hidden module: %s", mod);
        }
    }
    fclose(f);
}

static int pid_list_from_ps(int *pids, int max) {
    FILE *p = popen("ps -e -o pid", "r");
    if (!p) return -1;
    char line[256];
    int n = 0;
    fgets(line, sizeof(line), p); /* header */
    while (n < max && fgets(line, sizeof(line), p)) {
        pids[n++] = atoi(line);
    }
    pclose(p);
    return n;
}

static void check_hidden_processes(void) {
    int listed[16384];
    int count = pid_list_from_ps(listed, 16384);
    if (count < 0) {
        syslog(LOG_ERR, "ps error");
        return;
    }
    DIR *d = opendir("/proc");
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        int pid = atoi(de->d_name);
        int found = 0;
        for (int i = 0; i < count; i++) {
            if (listed[i] == pid) {
                found = 1;
                break;
            }
        }
        if (!found) {
            syslog(LOG_WARNING, "Hidden process: PID %d", pid);
        }
    }
    closedir(d);
}

static int collect_inodes(const char *path, unsigned long *inodes, int max) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[256];
    int n = 0;
    fgets(line, sizeof(line), f); /* header */
    while (n < max && fgets(line, sizeof(line), f)) {
        char *p = strrchr(line, ' ');
        if (!p) continue;
        unsigned long ino = strtoul(p, NULL, 10);
        inodes[n++] = ino;
    }
    fclose(f);
    return n;
}

static void check_fd_inodes(unsigned long *inodes, int icount, const char *label) {
    DIR *proc = opendir("/proc");
    if (!proc) return;
    struct dirent *de;
    char fdpath[PATH_MAX];
    char linkpath[PATH_MAX];
    char dest[PATH_MAX];
    while ((de = readdir(proc))) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        snprintf(fdpath, sizeof(fdpath), "/proc/%s/fd", de->d_name);
        DIR *fd = opendir(fdpath);
        if (!fd) continue;
        struct dirent *fde;
        while ((fde = readdir(fd))) {
            if (fde->d_name[0] == '.') continue;
            snprintf(linkpath, sizeof(linkpath), "%s/%s", fdpath, fde->d_name);
            ssize_t len = readlink(linkpath, dest, sizeof(dest) - 1);
            if (len <= 0) continue;
            dest[len] = '\0';
            unsigned long ino;
            if (sscanf(dest, "socket:[%lu]", &ino) == 1) {
                for (int i = 0; i < icount; i++) {
                    if (inodes[i] == ino) {
                        syslog(LOG_WARNING, "%s: PID %s", label, de->d_name);
                        break;
                    }
                }
            }
        }
        closedir(fd);
    }
    closedir(proc);
}

static void check_raw_sockets(void) {
    unsigned long inodes[1024];
    int count = collect_inodes("/proc/net/raw", inodes, 1024);
    if (count > 0)
        check_fd_inodes(inodes, count, "Raw socket");
}

static void check_suspicious_ports(void) {
    unsigned long inodes[1024];
    int count = 0;
    FILE *f = fopen("/proc/net/tcp", "r");
    if (f) {
        char line[512];
        fgets(line, sizeof(line), f);
        while (fgets(line, sizeof(line), f) && count < 1024) {
            char local[128];
            char st[8];
            unsigned long inode;
            sscanf(line, "%*d: %127s %*s %7s %*s %*s %*s %*s %*u %*u %lu", local, st, &inode);
            if (strcmp(st, "0A") == 0) {
                char *p = strchr(local, ':');
                int port = strtol(p + 1, NULL, 16);
                if (port == 31337 || port == 1337 || port == 1338) {
                    inodes[count++] = inode;
                }
            }
        }
        fclose(f);
    }
    if (count > 0)
        check_fd_inodes(inodes, count, "Suspicious port");
}

static void check_persistence(void) {
    const char *paths[] = {"/etc/rc.local", "/etc/crontab", NULL};
    const char *suspicious[] = {"/tmp", "/dev", "wget", "curl", NULL};
    char buf[4096];
    for (int i = 0; paths[i]; i++) {
        FILE *f = fopen(paths[i], "r");
        if (!f) continue;
        size_t len = fread(buf, 1, sizeof(buf) - 1, f);
        buf[len] = '\0';
        fclose(f);
        for (int j = 0; suspicious[j]; j++) {
            if (strstr(buf, suspicious[j])) {
                syslog(LOG_WARNING, "Persistence file %s contains %s", paths[i], suspicious[j]);
                break;
            }
        }
    }
}

static void check_systemd_services(void) {
    const char *dirs[] = {"/etc/systemd/system", "/usr/lib/systemd/system", NULL};
    const char *keywords[] = {"wget", "curl", "/tmp", "/dev", NULL};
    char path[PATH_MAX];
    char buf[4096];
    for (int i = 0; dirs[i]; i++) {
        DIR *d = opendir(dirs[i]);
        if (!d) continue;
        struct dirent *de;
        while ((de = readdir(d))) {
            if (!strstr(de->d_name, ".service")) continue;
            snprintf(path, sizeof(path), "%s/%s", dirs[i], de->d_name);
            FILE *f = fopen(path, "r");
            if (!f) continue;
            size_t len = fread(buf, 1, sizeof(buf) - 1, f);
            buf[len] = '\0';
            fclose(f);
            for (int j = 0; keywords[j]; j++) {
                if (strstr(buf, keywords[j])) {
                    syslog(LOG_WARNING, "Suspicious service: %s", path);
                    break;
                }
            }
        }
        closedir(d);
    }
}

#define BAD_IPS_FILE "/usr/share/sentinelroot/malicious_ips.json"

static int load_ips(const char *path, char ips[][64], int max) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[128];
    int n = 0;
    while (fgets(line, sizeof(line), f) && n < max) {
        char ip[64];
        if (sscanf(line, " \"%63[0-9.]:%*[^\n]\n", ip) == 1 ||
            sscanf(line, " \"%63[0-9.]\"", ip) == 1 ||
            sscanf(line, "%63[0-9.]", ip) == 1) {
            ip[strcspn(ip, ",\n")] = '\0';
            strncpy(ips[n++], ip, 63);
            ips[n-1][63] = '\0';
        }
    }
    fclose(f);
    return n;
}

static void hex_to_ip(const char *hex, char *out) {
    unsigned int a, b, c, d;
    if (sscanf(hex, "%2X%2X%2X%2X", &d, &c, &b, &a) == 4) {
        snprintf(out, 16, "%u.%u.%u.%u", a, b, c, d);
    } else {
        out[0] = '\0';
    }
}

static void check_network_patterns(void) {
    char ips[256][64];
    int icount = load_ips(BAD_IPS_FILE, ips, 256);
    if (icount <= 0) return;
    unsigned long bad[1024];
    int count = 0;
    FILE *f = fopen("/proc/net/tcp", "r");
    if (!f) return;
    char line[512];
    fgets(line, sizeof(line), f);
    while (fgets(line, sizeof(line), f) && count < 1024) {
        char local[128];
        char remote[128];
        unsigned long inode;
        if (sscanf(line, "%*d: %127s %127s %*s %*s %*s %*s %*s %*u %*u %lu", local, remote, &inode) != 3)
            continue;
        char hex[9];
        strncpy(hex, remote, 8);
        hex[8] = '\0';
        char ip[32];
        hex_to_ip(hex, ip);
        for (int i = 0; i < icount; i++) {
            if (strcmp(ip, ips[i]) == 0) {
                bad[count++] = inode;
                break;
            }
        }
    }
    fclose(f);
    if (count > 0)
        check_fd_inodes(bad, count, "Bad IP connection");
}

static void check_kernel_kprobes(void) {
    const char *path = "/sys/kernel/debug/kprobes/list";
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';
        if (*line)
            syslog(LOG_WARNING, "kprobe: %s", line);
    }
    fclose(f);
}

static void check_suspicious_cmdline(void) {
    const char *keywords[] = {"curl", "wget", "nc", "bash", "sh", "python", "perl", "ruby", "base64", NULL};
    DIR *d = opendir("/proc");
    if (!d) return;
    struct dirent *de;
    char path[PATH_MAX];
    char buf[4096];
    while ((de = readdir(d))) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        snprintf(path, sizeof(path), "/proc/%s/cmdline", de->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        size_t len = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        if (len == 0) continue;
        for (size_t i = 0; i < len - 1; i++)
            if (buf[i] == '\0') buf[i] = ' ';
        buf[len] = '\0';
        for (int j = 0; keywords[j]; j++) {
            if (strstr(buf, keywords[j])) {
                syslog(LOG_WARNING, "Suspicious cmdline: PID %s: %s", de->d_name, buf);
                break;
            }
        }
    }
    closedir(d);
}

static void check_process_resources(void) {
    DIR *d = opendir("/proc");
    if (!d) return;
    struct dirent *de;
    char path[PATH_MAX];
    unsigned long rss;
    long pagesize = sysconf(_SC_PAGESIZE);
    while ((de = readdir(d))) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        snprintf(path, sizeof(path), "/proc/%s/statm", de->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        if (fscanf(f, "%*s %lu", &rss) == 1) {
            if (rss * pagesize > 100 * 1024 * 1024) {
                syslog(LOG_WARNING, "High memory: PID %s - %lu MB", de->d_name,
                       (rss * pagesize) / (1024 * 1024));
            }
        }
        fclose(f);
    }
    closedir(d);
}

static void check_known_process_signatures(void) {
    DIR *d = opendir("/proc");
    if (!d) return;
    struct dirent *de;
    char path[PATH_MAX];
    char buf[256];
    while ((de = readdir(d))) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        int suspicious = 0;
        snprintf(path, sizeof(path), "/proc/%s/comm", de->d_name);
        FILE *f = fopen(path, "r");
        if (f) {
            if (fgets(buf, sizeof(buf), f))
                buf[strcspn(buf, "\n")] = '\0';
            fclose(f);
            for (int i = 0; EVIL_PROCESS_SIGNATURES[i]; i++) {
                if (strstr(buf, EVIL_PROCESS_SIGNATURES[i])) {
                    suspicious = 1;
                    break;
                }
            }
        }
        if (!suspicious) {
            snprintf(path, sizeof(path), "/proc/%s/exe", de->d_name);
            ssize_t len = readlink(path, buf, sizeof(buf) - 1);
            if (len > 0) {
                buf[len] = '\0';
                for (int i = 0; EVIL_PROCESS_SIGNATURES[i]; i++) {
                    if (strstr(buf, EVIL_PROCESS_SIGNATURES[i])) {
                        suspicious = 1;
                        break;
                    }
                }
            }
        }
        if (suspicious) {
            syslog(LOG_WARNING, "Known bad process: PID %s", de->d_name);
        }
    }
    closedir(d);
}

static void kill_evil_processes(void) {
    DIR *d = opendir("/proc");
    if (!d) return;
    struct dirent *de;
    char path[PATH_MAX];
    char buf[256];
    while ((de = readdir(d))) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        int pid = atoi(de->d_name);
        int suspicious = 0;
        snprintf(path, sizeof(path), "/proc/%s/comm", de->d_name);
        FILE *f = fopen(path, "r");
        if (f) {
            if (fgets(buf, sizeof(buf), f))
                buf[strcspn(buf, "\n")] = '\0';
            fclose(f);
            for (int i = 0; EVIL_PROCESS_SIGNATURES[i]; i++) {
                if (strstr(buf, EVIL_PROCESS_SIGNATURES[i])) {
                    suspicious = 1;
                    break;
                }
            }
        }
        if (!suspicious) {
            snprintf(path, sizeof(path), "/proc/%s/exe", de->d_name);
            ssize_t len = readlink(path, buf, sizeof(buf) - 1);
            if (len > 0) {
                buf[len] = '\0';
                for (int i = 0; EVIL_PROCESS_SIGNATURES[i]; i++) {
                    if (strstr(buf, EVIL_PROCESS_SIGNATURES[i])) {
                        suspicious = 1;
                        break;
                    }
                }
            }
        }
        if (suspicious) {
            kill(pid, SIGKILL);
            syslog(LOG_CRIT, "Killed process: PID %d", pid);
        }
    }
    closedir(d);
}

int main(void) {
    openlog("sentinelroot", LOG_PID | LOG_CONS, LOG_USER);
    check_ld_preload();
    check_tmp_exec();
    check_hidden_modules();
    check_hidden_processes();
    check_raw_sockets();
    check_suspicious_ports();
    check_persistence();
    check_systemd_services();
    check_network_patterns();
    check_kernel_kprobes();
    check_suspicious_cmdline();
    check_process_resources();
    check_known_process_signatures();
    kill_evil_processes();
    closelog();
    return 0;
}
