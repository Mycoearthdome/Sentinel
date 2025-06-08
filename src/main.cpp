#include <QApplication>
#include <QMainWindow>
#include <QTextEdit>
#include <QStringList>
#include <QProcess>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSet>
#include <cstdlib>

void checkLdPreload(QStringList &report) {
    const char *env = std::getenv("LD_PRELOAD");
    if (env && *env) {
        report << QString("LD_PRELOAD env: %1").arg(env);
    }
    QFile f("/etc/ld.so.preload");
    if (f.open(QIODevice::ReadOnly)) {
        QByteArray data = f.readAll().trimmed();
        if (!data.isEmpty()) {
            report << QString("ld.so.preload: %1").arg(QString::fromLocal8Bit(data));
        }
    }
}

void checkTmpExec(QStringList &report) {
    QDir proc("/proc");
    QStringList entries = proc.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QString &pidStr : entries) {
        bool ok = false;
        int pid = pidStr.toInt(&ok);
        if (!ok) continue;
        QString exePath = QString("/proc/%1/exe").arg(pid);
        QFileInfo fi(exePath);
        QString realPath = fi.symLinkTarget();
        if (realPath.startsWith("/tmp") || realPath.startsWith("/dev") || realPath.startsWith("/run")) {
            report << QString("Executable from tmp: PID %1 -> %2").arg(pid).arg(realPath);
        }
    }
}

void checkHiddenModules(QStringList &report) {
    QProcess ps;
    ps.start("lsmod");
    ps.waitForFinished();
    QString output = ps.readAllStandardOutput();
    QStringList lines = output.split('\n', Qt::SkipEmptyParts);
    QSet<QString> listed;
    for (int i = 1; i < lines.size(); ++i) {
        listed.insert(lines[i].split(' ').first());
    }
    QFile f("/proc/modules");
    if (f.open(QIODevice::ReadOnly)) {
        while (!f.atEnd()) {
            QByteArray line = f.readLine();
            QString mod = QString::fromLocal8Bit(line).split(' ').first();
            if (!listed.contains(mod)) {
                report << QString("Hidden module: %1").arg(mod);
            }
        }
    }
}

void checkHiddenProcesses(QStringList &report) {
    QProcess ps;
    ps.start("ps", {"-e", "-o", "pid"});
    ps.waitForFinished();
    QString out = ps.readAllStandardOutput();
    QSet<int> listed;
    for (const QString &line : out.split('\n', Qt::SkipEmptyParts).mid(1)) {
        listed.insert(line.trimmed().toInt());
    }
    QDir proc("/proc");
    QStringList entries = proc.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QString &pidStr : entries) {
        bool ok=false; int pid = pidStr.toInt(&ok); if(!ok) continue;
        if (!listed.contains(pid)) {
            report << QString("Hidden process: PID %1").arg(pid);
        }
    }
}

QStringList runChecks() {
    QStringList report;
    checkLdPreload(report);
    checkTmpExec(report);
    checkHiddenModules(report);
    checkHiddenProcesses(report);
    return report;
}

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    QMainWindow window;
    QTextEdit *edit = new QTextEdit(&window);
    edit->setReadOnly(true);
    QStringList report = runChecks();
    edit->setPlainText(report.join("\n"));
    window.setCentralWidget(edit);
    window.resize(600,400);
    window.setWindowTitle("SentinelRoot Report");
    window.show();
    return app.exec();
}

