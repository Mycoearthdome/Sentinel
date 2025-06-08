#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/stat.h>
#include <limits.h>

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

int main(void) {
    openlog("sentinelroot", LOG_PID | LOG_CONS, LOG_USER);
    check_ld_preload();
    check_tmp_exec();
    check_hidden_modules();
    check_hidden_processes();
    check_raw_sockets();
    check_suspicious_ports();
    check_persistence();
    closelog();
    return 0;
}
