/* -*- mode: c++; c-basic-offset:4 -*-
    utils/gnupg.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-FileCopyrightText: 2020-2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "gnupg.h"

#include "assuan.h"
#include "compat.h"
#include "compliance.h"
#include "cryptoconfig.h"
#include "hex.h"

#include <libkleo_debug.h>

#include <KLocalizedString>

#include <QGpgME/CryptoConfig>
#include <QGpgME/Protocol>

#include <QByteArray>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QPointer>
#include <QProcess>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QString>
#include <QThread>

#include <gpgme++/engineinfo.h>
#include <gpgme++/error.h>
#include <gpgme++/key.h>

#include <gpg-error.h>

#ifdef Q_OS_WIN
#include "gnupg-registry.h"
#endif // Q_OS_WIN

#include <algorithm>
#include <array>

using namespace GpgME;

QString Kleo::gnupgHomeDirectory()
{
    static const QString homeDir = QString::fromUtf8(GpgME::dirInfo("homedir"));
    return homeDir;
}

QString Kleo::gnupgPrivateKeysDirectory()
{
    static const QString dir = QDir{gnupgHomeDirectory()}.filePath(QStringLiteral("private-keys-v1.d"));
    return dir;
}

int Kleo::makeGnuPGError(int code)
{
    return gpg_error(static_cast<gpg_err_code_t>(code));
}

static QString findGpgExe(GpgME::Engine engine, const QString &exe)
{
    const GpgME::EngineInfo info = GpgME::engineInfo(engine);
    return info.fileName() ? QFile::decodeName(info.fileName()) : QStandardPaths::findExecutable(exe);
}

QString Kleo::gpgConfPath()
{
    static const auto path = findGpgExe(GpgME::GpgConfEngine, QStringLiteral("gpgconf"));
    return path;
}

QString Kleo::gpgSmPath()
{
    static const auto path = findGpgExe(GpgME::GpgSMEngine, QStringLiteral("gpgsm"));
    return path;
}

QString Kleo::gpgPath()
{
    static const auto path = findGpgExe(GpgME::GpgEngine, QStringLiteral("gpg"));
    return path;
}

QStringList Kleo::gnupgFileWhitelist()
{
    return {
        // The obvious pubring
        QStringLiteral("pubring.gpg"),
        // GnuPG 2.1 pubring
        QStringLiteral("pubring.kbx"),
        // Trust in X509 Certificates
        QStringLiteral("trustlist.txt"),
        // Trustdb controls ownertrust and thus WOT validity
        QStringLiteral("trustdb.gpg"),
        // We want to update when smartcard status changes
        QStringLiteral("reader*.status"),
        // No longer used in 2.1 but for 2.0 we want this
        QStringLiteral("secring.gpg"),
        // Secret keys (living under private-keys-v1.d/)
        QStringLiteral("*.key"),
        // the keyboxd database
        QStringLiteral("pubring.db"),
        // Changes to the trustmodel / compliance mode might
        // affect validity so we check this, too.
        // Globbing for gpg.conf* here will trigger too often
        // as gpgconf creates files like gpg.conf.bak or
        // gpg.conf.tmp12312.gpgconf that should not trigger
        // a change.
        QStringLiteral("gpg.conf"),
        QStringLiteral("gpg.conf-?"),
        QStringLiteral("gpg.conf-?.?"),
    };
}

QStringList Kleo::gnupgFolderWhitelist()
{
    static const QDir gnupgHome{gnupgHomeDirectory()};
    return {
        gnupgHome.path(),
        gnupgPrivateKeysDirectory(),
        // for the keyboxd database
        gnupgHome.filePath(QStringLiteral("public-keys.d")),
    };
}

QString Kleo::gpg4winInstallPath()
{
#ifdef Q_OS_WIN
    // QApplication::applicationDirPath is only used as a fallback
    // to support the case where Kleopatra is not installed from
    // Gpg4win but Gpg4win is also installed.
    char *instDir = read_w32_registry_string("HKEY_LOCAL_MACHINE", "Software\\GPG4Win", "Install Directory");
    if (!instDir) {
        // Fallback to HKCU
        instDir = read_w32_registry_string("HKEY_CURRENT_USER", "Software\\GPG4Win", "Install Directory");
    }
    if (instDir) {
        QString ret = QString::fromLocal8Bit(instDir) + QStringLiteral("/bin");
        free(instDir);
        return ret;
    }
    qCDebug(LIBKLEO_LOG) << "Gpg4win not found. Falling back to Kleopatra instdir.";
#endif
    return QCoreApplication::applicationDirPath();
}

QString Kleo::gnupgInstallPath()
{
#ifdef Q_OS_WIN
    // QApplication::applicationDirPath is only used as a fallback
    // to support the case where Kleopatra is not installed from
    // Gpg4win but Gpg4win is also installed.
    char *instDir = read_w32_registry_string("HKEY_LOCAL_MACHINE", "Software\\GnuPG", "Install Directory");
    if (!instDir) {
        // Fallback to HKCU
        instDir = read_w32_registry_string("HKEY_CURRENT_USER", "Software\\GnuPG", "Install Directory");
    }
    if (instDir) {
        QString ret = QString::fromLocal8Bit(instDir) + QStringLiteral("/bin");
        free(instDir);
        return ret;
    }
    qCDebug(LIBKLEO_LOG) << "GnuPG not found. Falling back to gpgconf list dir.";
#endif
    return gpgConfListDir("bindir");
}

QString Kleo::gpgConfListDir(const char *which)
{
    if (!which || !*which) {
        return QString();
    }
    const QString gpgConfPath = Kleo::gpgConfPath();
    if (gpgConfPath.isEmpty()) {
        return QString();
    }
    QProcess gpgConf;
    qCDebug(LIBKLEO_LOG) << "gpgConfListDir: starting " << qPrintable(gpgConfPath) << " --list-dirs";
    gpgConf.start(gpgConfPath, QStringList() << QStringLiteral("--list-dirs"));
    if (!gpgConf.waitForFinished()) {
        qCDebug(LIBKLEO_LOG) << "gpgConfListDir(): failed to execute gpgconf: " << qPrintable(gpgConf.errorString());
        qCDebug(LIBKLEO_LOG) << "output was:\n" << gpgConf.readAllStandardError().constData();
        return QString();
    }
    const QList<QByteArray> lines = gpgConf.readAllStandardOutput().split('\n');
    for (const QByteArray &line : lines) {
        if (line.startsWith(which) && line[qstrlen(which)] == ':') {
            const int begin = qstrlen(which) + 1;
            int end = line.size();
            while (end && (line[end - 1] == '\n' || line[end - 1] == '\r')) {
                --end;
            }
            const QString result = QDir::fromNativeSeparators(QFile::decodeName(hexdecode(line.mid(begin, end - begin))));
            qCDebug(LIBKLEO_LOG) << "gpgConfListDir: found " << qPrintable(result) << " for '" << which << "'entry";
            return result;
        }
    }
    qCDebug(LIBKLEO_LOG) << "gpgConfListDir(): didn't find '" << which << "'"
                         << "entry in output:\n"
                         << gpgConf.readAllStandardError().constData();
    return QString();
}

static std::array<int, 3> getVersionFromString(const char *actual, bool &ok)
{
    std::array<int, 3> ret{-1, -1, -1};
    ok = false;

    if (!actual) {
        return ret;
    }

    QString versionString = QString::fromLatin1(actual);

    // Try to fix it up
    QRegularExpression rx(QRegularExpression::anchoredPattern(QLatin1StringView(R"((\d+)\.(\d+)\.(\d+)(?:-svn\d+)?.*)")));
    QRegularExpressionMatch match;
    for (int i = 0; i < 3; i++) {
        match = rx.match(versionString);
        if (!match.hasMatch()) {
            versionString += QStringLiteral(".0");
        } else {
            ok = true;
            break;
        }
    }

    if (!ok) {
        qCDebug(LIBKLEO_LOG) << "Can't parse version " << actual;
        return ret;
    }

    for (int i = 0; i < 3; ++i) {
        ret[i] = match.capturedView(i + 1).toUInt(&ok);
        if (!ok) {
            return ret;
        }
    }

    ok = true;
    return ret;
}

bool Kleo::versionIsAtLeast(const char *minimum, const char *actual)
{
    if (!minimum || !actual) {
        return false;
    }
    bool ok;
    const auto minimum_version = getVersionFromString(minimum, ok);
    if (!ok) {
        return false;
    }
    const auto actual_version = getVersionFromString(actual, ok);
    if (!ok) {
        return false;
    }

    return !std::lexicographical_compare(std::begin(actual_version), std::end(actual_version), std::begin(minimum_version), std::end(minimum_version));
}

bool Kleo::engineIsVersion(int major, int minor, int patch, GpgME::Engine engine)
{
    static QMap<Engine, std::array<int, 3>> cachedVersions;
    const int required_version[] = {major, minor, patch};
    // Gpgconf means spawning processes which is expensive on windows.
    std::array<int, 3> actual_version;
    if (!cachedVersions.contains(engine)) {
        const Error err = checkEngine(engine);
        if (err.code() == GPG_ERR_INV_ENGINE) {
            qCDebug(LIBKLEO_LOG) << "isVersion: invalid engine. '";
            return false;
        }

        const char *actual = GpgME::engineInfo(engine).version();
        bool ok;
        actual_version = getVersionFromString(actual, ok);

        qCDebug(LIBKLEO_LOG) << "Parsed" << actual << "as: " << actual_version[0] << '.' << actual_version[1] << '.' << actual_version[2] << '.';
        if (!ok) {
            return false;
        }
        cachedVersions.insert(engine, actual_version);
    } else {
        actual_version = cachedVersions.value(engine);
    }

    // return ! ( actual_version < required_version )
    return !std::lexicographical_compare(std::begin(actual_version), std::end(actual_version), std::begin(required_version), std::end(required_version));
}

const QString &Kleo::paperKeyInstallPath()
{
    static const QString pkPath = (QStandardPaths::findExecutable(QStringLiteral("paperkey"), QStringList() << QCoreApplication::applicationDirPath()).isEmpty()
                                       ? QStandardPaths::findExecutable(QStringLiteral("paperkey"))
                                       : QStandardPaths::findExecutable(QStringLiteral("paperkey"), QStringList() << QCoreApplication::applicationDirPath()));
    return pkPath;
}

bool Kleo::haveKeyserverConfigured()
{
    if (engineIsVersion(2, 4, 4) //
        || (engineIsVersion(2, 2, 42) && !engineIsVersion(2, 3, 0))) {
        return Kleo::keyserver() != QLatin1StringView{"none"};
    }
    if (engineIsVersion(2, 1, 19)) {
        // since 2.1.19 there is a builtin keyserver
        return true;
    }
    return !Kleo::keyserver().isEmpty();
}

QString Kleo::keyserver()
{
    QString result = getCryptoConfigStringValue("gpg", "keyserver");
    if (result.isEmpty()) {
        result = getCryptoConfigStringValue("dirmngr", "keyserver");
    }
    if (result.endsWith(QLatin1StringView{"://none"})) {
        // map hkps://none, etc., to "none"; see https://dev.gnupg.org/T6708
        result = QStringLiteral("none");
    }
    return result;
}

bool Kleo::haveX509DirectoryServerConfigured()
{
    return !getCryptoConfigUrlList("dirmngr", "ldapserver").empty() //
        || !getCryptoConfigUrlList("dirmngr", "LDAP Server").empty() //
        || !getCryptoConfigUrlList("gpgsm", "keyserver").empty();
}

bool Kleo::gpgComplianceP(const char *mode)
{
    const auto conf = QGpgME::cryptoConfig();
    const auto entry = getCryptoConfigEntry(conf, "gpg", "compliance");
    return entry && entry->stringValue() == QString::fromLatin1(mode);
}

bool Kleo::gnupgUsesDeVsCompliance()
{
    return DeVSCompliance::isActive();
}

bool Kleo::gnupgIsDeVsCompliant()
{
    return DeVSCompliance::isCompliant();
}

#ifdef Q_OS_WIN
static unsigned int guessConsoleOutputCodePage()
{
    /* Qt on Windows uses GetACP while GnuPG prefers
     * GetConsoleOutputCP.
     *
     * As we are not a console application GetConsoleOutputCP
     * usually returns 0.
     * From experience the closest thing that let's us guess
     * what GetConsoleOutputCP returns for a console application
     * it appears to be the OEMCP.
     */
    unsigned int cpno = GetConsoleOutputCP();
    if (!cpno) {
        cpno = GetOEMCP();
    }
    if (!cpno) {
        cpno = GetACP();
    }
    if (!cpno) {
        qCDebug(LIBKLEO_LOG) << __func__ << "Failed to find native codepage";
    }

    qCDebug(LIBKLEO_LOG) << __func__ << "returns" << cpno;
    return cpno;
}

static QString fromEncoding(unsigned int src_encoding, const char *data)
{
    if (!data || !*data) {
        return {};
    }

    // returns necessary buffer size including the terminating null character
    int n = MultiByteToWideChar(src_encoding, 0, data, -1, NULL, 0);
    if (n <= 0) {
        qCDebug(LIBKLEO_LOG) << __func__ << "determining necessary buffer size failed with error code" << GetLastError();
        return QString();
    }

    wchar_t *result = (wchar_t *)malloc((n + 1) * sizeof *result);

    n = MultiByteToWideChar(src_encoding, 0, data, -1, result, n);
    if (n <= 0) {
        free(result);
        qCDebug(LIBKLEO_LOG) << __func__ << "conversion failed with error code" << GetLastError();
        return QString();
    }
    const auto ret = QString::fromWCharArray(result, n - 1);
    free(result);
    return ret;
}

static QString stringFromGpgOutput_legacy(const QByteArray &ba)
{
    static const unsigned int cpno = guessConsoleOutputCodePage();

    if (cpno) {
        qCDebug(LIBKLEO_LOG) << __func__ << "trying to decode" << ba << "using codepage" << cpno;
        const auto rawData = QByteArray{ba}.replace("\r\n", "\n");
        const auto s = fromEncoding(cpno, rawData.constData());
        if (!s.isEmpty() || ba.isEmpty()) {
            return s;
        }
        qCDebug(LIBKLEO_LOG) << __func__ << "decoding output failed; falling back to QString::fromLocal8Bit()";
    }
    qCDebug(LIBKLEO_LOG) << __func__ << "decoding from local encoding:" << ba;
    return QString::fromLocal8Bit(ba);
}
#endif

QString Kleo::stringFromGpgOutput(const QByteArray &ba)
{
#ifdef Q_OS_WIN
    // since 2.2.28, GnuPG always uses UTF-8 for console output (and input)
    if (Kleo::engineIsVersion(2, 2, 28, GpgME::GpgEngine)) {
        return QString::fromUtf8(ba);
    } else {
        return stringFromGpgOutput_legacy(ba);
    }
#else
    return QString::fromLocal8Bit(ba);
#endif
}

QStringList Kleo::backendVersionInfo()
{
    QStringList versions;
    if (Kleo::engineIsVersion(2, 2, 24, GpgME::GpgConfEngine)) {
        QProcess p;
        qCDebug(LIBKLEO_LOG) << "Running gpgconf --show-versions ...";
        p.start(Kleo::gpgConfPath(), {QStringLiteral("--show-versions")});
        // wait at most 1 second
        if (!p.waitForFinished(1000)) {
            qCDebug(LIBKLEO_LOG) << "Running gpgconf --show-versions timed out after 1 second.";
        } else if (p.exitStatus() != QProcess::NormalExit || p.exitCode() != 0) {
            qCDebug(LIBKLEO_LOG) << "Running gpgconf --show-versions failed:" << p.errorString();
            qCDebug(LIBKLEO_LOG) << "gpgconf stderr:" << p.readAllStandardError();
            qCDebug(LIBKLEO_LOG) << "gpgconf stdout:" << p.readAllStandardOutput();
        } else {
            const QByteArray output = p.readAllStandardOutput().replace("\r\n", "\n");
            qCDebug(LIBKLEO_LOG) << "gpgconf stdout:" << output;
            const auto lines = output.split('\n');
            for (const auto &line : lines) {
                if (line.startsWith("* GnuPG") || line.startsWith("* Libgcrypt")) {
                    const auto components = line.split(' ');
                    versions.push_back(QString::fromLatin1(components.at(1) + ' ' + components.value(2)));
                }
            }
        }
    }
    return versions;
}

namespace
{

void runGpgConf(const QStringList &arguments)
{
    QProcess process;
    process.setProgram(Kleo::gpgConfPath());
    process.setArguments(arguments);

    qCDebug(LIBKLEO_LOG) << "Starting gpgconf (" << &process << ") with arguments" << process.arguments().join(QLatin1Char(' ')) << " ...";
    process.start();

    if (!process.waitForStarted(5000 /* wait at most 5 seconds */)) {
        qCDebug(LIBKLEO_LOG) << "gpgconf failed to start:" << process.errorString() << "\nstderr:" << process.readAllStandardError();
        return;
    }
    if (!process.waitForFinished(5000 /* wait at most 5 seconds */)) {
        qCDebug(LIBKLEO_LOG) << "gpgconf did not exit after 5 seconds:" << process.errorString() << "\nstderr:" << process.readAllStandardError();
        return;
    }
    qCDebug(LIBKLEO_LOG) << "gpgconf (" << &process << ") exited with exit code" << process.exitCode() << ")";
    if (process.exitCode() > 0) {
        qCDebug(LIBKLEO_LOG) << "gpgconf stderr:" << process.readAllStandardError();
    }
}

template<typename Function1, typename Function2>
auto startGpgConf(const QStringList &arguments, Function1 onSuccess, Function2 onFailure)
{
    auto process = new QProcess;
    process->setProgram(Kleo::gpgConfPath());
    process->setArguments(arguments);

    QObject::connect(process, &QProcess::started, [process]() {
        qCDebug(LIBKLEO_LOG).nospace() << "gpgconf (" << process << ") was started successfully";
    });
    QObject::connect(process, &QProcess::errorOccurred, [process, onFailure](auto error) {
        qCDebug(LIBKLEO_LOG).nospace() << "Error while running gpgconf (" << process << "): " << error;
        process->deleteLater();
        onFailure();
    });
    QObject::connect(process, &QProcess::readyReadStandardError, [process]() {
        for (const auto &line : process->readAllStandardError().trimmed().split('\n')) {
            qCDebug(LIBKLEO_LOG).nospace() << "gpgconf (" << process << ") stderr: " << line;
        }
    });
    QObject::connect(process, &QProcess::readyReadStandardOutput, [process]() {
        (void)process->readAllStandardOutput(); /* ignore stdout */
    });
    QObject::connect(process, &QProcess::finished, [process, onSuccess, onFailure](int exitCode, QProcess::ExitStatus exitStatus) {
        if (exitStatus == QProcess::NormalExit) {
            qCDebug(LIBKLEO_LOG).nospace() << "gpgconf (" << process << ") exited (exit code: " << exitCode << ")";
            if (exitCode == 0) {
                onSuccess();
            } else {
                onFailure();
            }
        } else {
            qCDebug(LIBKLEO_LOG).nospace() << "gpgconf (" << process << ") crashed (exit code: " << exitCode << ")";
            onFailure();
        }
        process->deleteLater();
    });

    qCDebug(LIBKLEO_LOG).nospace() << "Starting gpgconf (" << process << ") with arguments " << process->arguments().join(QLatin1Char(' ')) << " ...";
    process->start();

    return process;
}

static void launchGpgAgentWithEventLoop()
{
    static thread_local QProcess *process = nullptr;
    static thread_local qint64 mSecsSinceEpochOfLastLaunch = 0;
    static thread_local int numberOfFailedLaunches = 0;

    if (process) {
        qCDebug(LIBKLEO_LOG) << __func__ << ": gpg-agent is already being launched";
        return;
    }
    const auto now = QDateTime::currentMSecsSinceEpoch();
    if (now - mSecsSinceEpochOfLastLaunch < 1000) {
        // reduce attempts to launch the agent to 1 attempt per second
        return;
    }
    mSecsSinceEpochOfLastLaunch = now;
    if (numberOfFailedLaunches > 5) {
        qCWarning(LIBKLEO_LOG) << __func__ << ": Launching gpg-agent failed" << numberOfFailedLaunches << "times in a row. Giving up.";
        return;
    }

    process = startGpgConf(
        {QStringLiteral("--launch"), QStringLiteral("gpg-agent")},
        []() {
            numberOfFailedLaunches = 0;
            process = nullptr;
        },
        []() {
            numberOfFailedLaunches++;
            process = nullptr;
        });
}
}

void Kleo::launchGpgAgent(Kleo::LaunchGpgAgentOptions options)
{
    if ((options == CheckForRunningAgent) && Kleo::Assuan::agentIsRunning()) {
        qCDebug(LIBKLEO_LOG) << __func__ << ": gpg-agent is already running";
        return;
    }

    if (QThread::currentThread()->loopLevel() > 0) {
        launchGpgAgentWithEventLoop();
    } else {
        runGpgConf({QStringLiteral("--launch"), QStringLiteral("gpg-agent")});
    }
}

void Kleo::restartGpgAgent()
{
    static QPointer<QProcess> process;

    if (process) {
        qCDebug(LIBKLEO_LOG) << __func__ << ": gpg-agent is already being restarted";
        return;
    }

    auto startAgent = []() {
        Kleo::launchGpgAgent(SkipCheckForRunningAgent);
    };
    process = startGpgConf({QStringLiteral("--kill"), QStringLiteral("all")}, startAgent, startAgent);
}

const std::vector<std::string> &Kleo::availableAlgorithms()
{
    static const std::vector<std::string> algos = {
        "brainpoolP256r1",
        "brainpoolP384r1",
        "brainpoolP512r1",
        "curve25519",
        "curve448",
        "nistp256",
        "nistp384",
        "nistp521",
        "rsa2048",
        "rsa3072",
        "rsa4096",
        // "secp256k1", // Curve secp256k1 is explicitly ignored
    };
    return algos;
}

const std::vector<std::string> &Kleo::preferredAlgorithms()
{
    static const std::vector<std::string> algos = {
        "curve25519",
        "brainpoolP256r1",
        "rsa3072",
        "rsa2048",
    };
    return algos;
}

const std::vector<std::string> &Kleo::ignoredAlgorithms()
{
    static const std::vector<std::string> algos = {
        "secp256k1", // Curve secp256k1 is not useful
    };
    return algos;
}

bool Kleo::gpgvVerify(const QString &filePath, const QString &sigPath, const QString &keyring, const QStringList &additionalSearchPaths)
{
    const QFileInfo verifyFi(filePath);
    if (!verifyFi.isReadable()) {
        return false;
    } else {
        qCDebug(LIBKLEO_LOG) << "Verifying" << filePath;
    }

    const auto gpgvPath = QStandardPaths::findExecutable(QStringLiteral("gpgv"), additionalSearchPaths);
    if (gpgvPath.isEmpty()) {
        qCDebug(LIBKLEO_LOG) << "Could not find gpgv";
        return false;
    }

    QFileInfo sigFi;
    if (!sigPath.isEmpty()) {
        sigFi.setFile(sigPath);
    } else {
        sigFi.setFile(filePath + QStringLiteral(".sig"));
    }

    if (!sigFi.isReadable()) {
        qCDebug(LIBKLEO_LOG) << "No signature found at" << sigFi.absoluteFilePath();
        return false;
    }

    auto process = QProcess();
    process.setProgram(gpgvPath);
    QStringList args;
    if (!keyring.isEmpty()) {
        args << QStringLiteral("--keyring") << keyring;
    }
    args << QStringLiteral("--") << sigFi.absoluteFilePath() << verifyFi.absoluteFilePath();
    process.setArguments(args);
    qCDebug(LIBKLEO_LOG).nospace() << "Starting gpgv (" << gpgvPath << ") with arguments " << args.join(QLatin1Char(' ')) << " ...";
    process.start();

    if (!process.waitForFinished(-1)) {
        qCDebug(LIBKLEO_LOG) << "Failed to execute gpgv" << process.errorString();
    }
    bool ret = (process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0);

    if (!ret) {
        qCDebug(LIBKLEO_LOG) << "Failed to verify file";
        qCDebug(LIBKLEO_LOG) << "gpgv stdout:" << QString::fromUtf8(process.readAllStandardOutput());
        qCDebug(LIBKLEO_LOG) << "gpgv stderr:" << QString::fromUtf8(process.readAllStandardError());
    }
    return ret;
}

std::vector<QByteArray> Kleo::readSecretKeyFile(const QString &keyGrip)
{
    const auto filename = QStringLiteral("%1.key").arg(keyGrip);
    const auto path = QDir{Kleo::gnupgPrivateKeysDirectory()}.filePath(filename);

    QFile file{path};
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qCDebug(LIBKLEO_LOG) << "Cannot open the private key file" << path << "for reading";
        return {};
    }

    std::vector<QByteArray> lines;
    while (!file.atEnd()) {
        lines.push_back(file.readLine());
    }
    if (lines.empty()) {
        qCDebug(LIBKLEO_LOG) << "The private key file" << path << "is empty";
    }
    return lines;
}
