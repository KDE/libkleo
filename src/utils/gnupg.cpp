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
#include <QRegExp>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QString>

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
    };
}

namespace
{
class Gpg4win
{
public:
    static const Gpg4win *instance()
    {
        // We use singleton to do the signature check only once.
        static Gpg4win *inst = nullptr;
        if (!inst) {
            inst = new Gpg4win();
        }
        return inst;
    }

private:
    QString mVersion;
    QString mDescription;
    QString mDescLong;
    QString mBrandingWindowTitle;
    QString mBrandingIcon;
    bool mSignedVersion;

    Gpg4win()
        : mVersion(QStringLiteral("Unknown Windows Version"))
        , mDescription(i18n("Certificate Manager and Unified Crypto GUI"))
        , mDescLong(QStringLiteral("<a href=https://www.gpg4win.org>Visit the Gpg4win homepage</a>"))
        , mSignedVersion(false)
    {
        const QString instPath = Kleo::gpg4winInstallPath();
        const QString verPath = instPath + QStringLiteral("/../VERSION");
        QFile versionFile(verPath);

        // Open the file first to avoid a verify and then read issue where
        // "auditors" might say its an issue,...
        if (!versionFile.open(QIODevice::ReadOnly)) {
            return;
        }
        // Expect a three line format of three HTML strings.
        const auto versVersion = QString::fromUtf8(versionFile.readLine()).trimmed();
        const auto versDescription = QString::fromUtf8(versionFile.readLine()).trimmed();
        const auto versDescLong = QString::fromUtf8(versionFile.readLine()).trimmed();
        // read optional two branding strings
        const auto brandingWindowTitle = QString::fromUtf8(versionFile.readLine()).trimmed();
        const auto brandingIcon = QString::fromUtf8(versionFile.readLine()).trimmed();

        const QString sigPath = verPath + QStringLiteral(".sig");
        QFileInfo versionSig(instPath + QStringLiteral("/../VERSION.sig"));
        if (versionSig.exists()) {
            /* We have a signed version so let us check it against the GnuPG
             * release keys. */
            QProcess gpgv;
            gpgv.setProgram(Kleo::gpgPath().replace(QStringLiteral("gpg.exe"), QStringLiteral("gpgv.exe")));
            const QString keyringPath(QStringLiteral("%1/../share/gnupg/distsigkey.gpg").arg(Kleo::gnupgInstallPath()));
            gpgv.setArguments(QStringList() << QStringLiteral("--keyring") << keyringPath << QStringLiteral("--") << sigPath << verPath);
            gpgv.start();
            gpgv.waitForFinished();
            if (gpgv.exitStatus() == QProcess::NormalExit && !gpgv.exitCode()) {
                qCDebug(LIBKLEO_LOG) << "Valid Version: " << versVersion;
                mVersion = versVersion;
                mDescription = versDescription;
                mDescLong = versDescLong;
                mBrandingWindowTitle = brandingWindowTitle;
                mBrandingIcon = brandingIcon;
                mSignedVersion = true;
            } else {
                qCDebug(LIBKLEO_LOG) << "gpgv failed with stderr: " << gpgv.readAllStandardError();
                qCDebug(LIBKLEO_LOG) << "gpgv stdout" << gpgv.readAllStandardOutput();
            }
        } else {
            qCDebug(LIBKLEO_LOG) << "No signed VERSION file found.";
        }
        // Also take Version information from unsigned Versions.
        mVersion = versVersion;
    }

public:
    const QString &version() const
    {
        return mVersion;
    }
    const QString &description() const
    {
        return mDescription;
    }
    const QString &longDescription() const
    {
        return mDescLong;
    }
    bool isSignedVersion() const
    {
        return mSignedVersion;
    }
    const QString &brandingWindowTitle() const
    {
        return mBrandingWindowTitle;
    }
    const QString &brandingIcon() const
    {
        return mBrandingIcon;
    }
};
} // namespace

bool Kleo::gpg4winSignedversion()
{
    return Gpg4win::instance()->isSignedVersion();
}

QString Kleo::gpg4winVersionNumber()
{
    // extract the actual version number from the string returned by Gpg4win::version();
    // we assume that Gpg4win::version() returns a version number (conforming to the semantic
    // versioning spec) optionally prefixed with some text followed by a dash,
    // e.g. "Gpg4win-3.1.15-beta15"; see https://dev.gnupg.org/T5663
    static const QRegularExpression catchSemVerRegExp{QLatin1String{R"(-([0-9]+(?:\.[0-9]+)*(?:-[.0-9A-Za-z-]+)?(?:\+[.0-9a-zA-Z-]+)?)$)"}};

    QString ret;
    const auto match = catchSemVerRegExp.match(gpg4winVersion());
    if (match.hasMatch()) {
        ret = match.captured(1);
    } else {
        ret = gpg4winVersion();
    }
    qCDebug(LIBKLEO_LOG) << __func__ << "returns" << ret;
    return ret;
}

QString Kleo::gpg4winVersion()
{
    return Gpg4win::instance()->version();
}
QString Kleo::gpg4winDescription()
{
    return Gpg4win::instance()->description();
}
QString Kleo::gpg4winLongDescription()
{
    return Gpg4win::instance()->longDescription();
}

QString Kleo::brandingWindowTitle()
{
    return Gpg4win::instance()->brandingWindowTitle();
}
QString Kleo::brandingIcon()
{
    return Gpg4win::instance()->brandingIcon();
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
    std::array<int, 3> ret;
    ok = false;

    if (!actual) {
        return ret;
    }

    QString versionString = QString::fromLatin1(actual);

    // Try to fix it up
    QRegExp rx(QLatin1String(R"((\d+)\.(\d+)\.(\d+)(?:-svn\d+)?.*)"));
    for (int i = 0; i < 3; i++) {
        if (!rx.exactMatch(versionString)) {
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
        ret[i] = rx.cap(i + 1).toUInt(&ok);
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
static unsigned int gpgConfGetConsoleOutputCodePage()
{
    // calls `gpgconf --show-codepages` to determine the console output codepage used by gpg on Windows;
    // for other OSs gpgconf returns nothing
    const auto gpgConfPath = Kleo::gpgConfPath();
    if (gpgConfPath.isEmpty()) {
        return 0;
    }
    QProcess gpgConf;
    qCDebug(LIBKLEO_LOG) << __func__ << "starting" << gpgConfPath << "--show-codepages";
    gpgConf.start(gpgConfPath, {QStringLiteral("--show-codepages")});
    if (!gpgConf.waitForFinished()) {
        qCDebug(LIBKLEO_LOG) << __func__ << "failed to execute gpgconf:" << gpgConf.errorString() << "\nstderr:" << gpgConf.readAllStandardError();
        return 0;
    }

    unsigned int cpno = 0;
    const auto lines = gpgConf.readAllStandardOutput().split('\n');
    // look for a line of the form "Console: CP%u" or "Console: CP%u/CP%u"
    for (const auto &l : lines) {
        if (l.startsWith("Console: CP")) {
            // the console output codepage is the second CP value if there are two
            cpno = l.mid(l.lastIndexOf("CP") + 2).toUInt();
            break;
        }
    }
    // if ConsoleOutputCP is 0 fall back to ACP (as gpg does in set_native_charset)
    if (cpno == 0) {
        qCDebug(LIBKLEO_LOG) << __func__ << "ConsoleOutputCP is" << cpno << "- use ACP";
        // look for a line of the form "ANSI: CP%u"
        for (const auto &l : lines) {
            if (l.startsWith("ANSI: CP")) {
                cpno = l.mid(l.indexOf("CP") + 2).toUInt();
                break;
            }
        }
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
#endif

QString Kleo::stringFromGpgOutput(const QByteArray &ba)
{
#ifdef Q_OS_WIN
    static const unsigned int cpno = gpgConfGetConsoleOutputCodePage();

    if (cpno) {
        qCDebug(LIBKLEO_LOG) << __func__ << "trying to decode" << ba << "using codepage" << cpno;
        const auto rawData = QByteArray{ba}.replace("\r\n", "\n");
        const auto s = fromEncoding(cpno, rawData.constData());
        if (!s.isEmpty() || ba.isEmpty()) {
            return s;
        }
        qCDebug(LIBKLEO_LOG) << __func__ << "decoding output failed; falling back to QString::fromLocal8Bit()";
    }
#endif
    return QString::fromLocal8Bit(ba);
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
            qCDebug(LIBKLEO_LOG) << "gpgconf stdout:" << p.readAllStandardOutput();
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
    QObject::connect(process,
                     qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
                     [process, onSuccess, onFailure](int exitCode, QProcess::ExitStatus exitStatus) {
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

static auto startGpgConf(const QStringList &arguments)
{
    return startGpgConf(
        arguments,
        []() {},
        []() {});
}

}

void Kleo::launchGpgAgent()
{
    static QPointer<QProcess> process;
    static qint64 mSecsSinceEpochOfLastLaunch = 0;
    static int numberOfFailedLaunches = 0;

    if (Kleo::Assuan::agentIsRunning()) {
        qCDebug(LIBKLEO_LOG) << __func__ << ": gpg-agent is already running";
        return;
    }
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
        },
        []() {
            numberOfFailedLaunches++;
        });
}

void Kleo::killDaemons()
{
    static QPointer<QProcess> process;

    if (process) {
        qCDebug(LIBKLEO_LOG) << __func__ << ": The daemons are already being shut down";
        return;
    }

    process = startGpgConf({QStringLiteral("--kill"), QStringLiteral("all")});
}
