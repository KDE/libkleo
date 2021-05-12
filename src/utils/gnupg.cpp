/* -*- mode: c++; c-basic-offset:4 -*-
    utils/gnupg.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-FileCopyrightText: 2020 g10 Code GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "gnupg.h"

#include "utils/compat.h"
#include "utils/hex.h"

#include <gpgme++/engineinfo.h>
#include <gpgme++/error.h>
#include <gpgme++/key.h>

#include <QGpgME/Protocol>
#include <QGpgME/CryptoConfig>

#include "libkleo_debug.h"

#include <QDir>
#include <QFile>
#include <QString>
#include <QProcess>
#include <QByteArray>
#include <QStandardPaths>
#include <QCoreApplication>
#include <gpg-error.h>

#ifdef Q_OS_WIN
#include "gnupg-registry.h"
#endif // Q_OS_WIN

#include <algorithm>
#include <array>

#include <KLocalizedString>

using namespace GpgME;

QString Kleo::gnupgHomeDirectory()
{
    static QString homeDir = QString::fromUtf8(GpgME::dirInfo("homedir"));
    return homeDir;
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
    return QStringList()
           // The obvious pubring
           << QStringLiteral("pubring.gpg")
           // GnuPG 2.1 pubring
           << QStringLiteral("pubring.kbx")
           // Trust in X509 Certificates
           << QStringLiteral("trustlist.txt")
           // Trustdb controls ownertrust and thus WOT validity
           << QStringLiteral("trustdb.gpg")
           // We want to update when smartcard status changes
           << QStringLiteral("reader*.status")
           // No longer used in 2.1 but for 2.0 we want this
           << QStringLiteral("secring.gpg")
           // Changes to the trustmodel / compliance mode might
           // affect validity so we check this, too.
           // Globbing for gpg.conf* here will trigger too often
           // as gpgconf creates files like gpg.conf.bak or
           // gpg.conf.tmp12312.gpgconf that should not trigger
           // a change.
           << QStringLiteral("gpg.conf")
           << QStringLiteral("gpg.conf-?")
           << QStringLiteral("gpg.conf-?.?")
           ;
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
    bool mSignedVersion;

    Gpg4win() :
        mVersion(QStringLiteral("Unknown Windows Version")),
        mDescription(i18n("Certificate Manager and Unified Crypto GUI")),
        mDescLong(QStringLiteral("<a href=https://www.gpg4win.org>Visit the Gpg4win homepage</a>")),
        mSignedVersion(false)
    {
        const QString instPath = Kleo::gpg4winInstallPath();
        const QString verPath = instPath + QStringLiteral("/../VERSION");
        QFile versionFile(verPath);

        QString versVersion;
        QString versDescription;
        QString versDescLong;
        // Open the file first to avoid a verify and then read issue where
        // "auditors" might say its an issue,...
        if (!versionFile.open(QIODevice::ReadOnly)) {
            // No need to translate this should only be the case in development
            // builds.
            return;
        } else {
            // Expect a three line format of three HTML strings.
            versVersion = QString::fromUtf8(versionFile.readLine()).trimmed();
            versDescription = QString::fromUtf8(versionFile.readLine()).trimmed();
            versDescLong = QString::fromUtf8(versionFile.readLine()).trimmed();
        }

        const QString sigPath = verPath + QStringLiteral(".sig");
        QFileInfo versionSig(instPath + QStringLiteral("/../VERSION.sig"));
        if (versionSig.exists()) {
            /* We have a signed version so let us check it against the GnuPG
             * release keys. */
            QProcess gpgv;
            gpgv.setProgram(Kleo::gpgPath().replace(QStringLiteral("gpg.exe"), QStringLiteral("gpgv.exe")));
            const QString keyringPath(QStringLiteral("%1/../share/gnupg/distsigkey.gpg").arg(Kleo::gnupgInstallPath()));
            gpgv.setArguments(QStringList() << QStringLiteral("--keyring")
                                            << keyringPath
                                            << QStringLiteral("--")
                                            << sigPath
                                            << verPath);
            gpgv.start();
            gpgv.waitForFinished();
            if (gpgv.exitStatus() == QProcess::NormalExit &&
                !gpgv.exitCode()) {
                qCDebug(LIBKLEO_LOG) << "Valid Version: " << versVersion;
                mVersion = versVersion;
                mDescription = versDescription;
                mDescLong = versDescLong;
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
};
} // namespace

bool Kleo::gpg4winSignedversion()
{
    return Gpg4win::instance()->isSignedVersion();
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

QString Kleo::gpg4winInstallPath()
{
#ifdef Q_OS_WIN
    // QApplication::applicationDirPath is only used as a fallback
    // to support the case where Kleopatra is not installed from
    // Gpg4win but Gpg4win is also installed.
    char *instDir = read_w32_registry_string("HKEY_LOCAL_MACHINE",
                                             "Software\\GPG4Win",
                                             "Install Directory");
    if (!instDir) {
        // Fallback to HKCU
        instDir = read_w32_registry_string("HKEY_CURRENT_USER",
                                           "Software\\GPG4Win",
                                           "Install Directory");
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
    char *instDir = read_w32_registry_string("HKEY_LOCAL_MACHINE",
                                             "Software\\GnuPG",
                                             "Install Directory");
    if (!instDir) {
        // Fallback to HKCU
        instDir = read_w32_registry_string("HKEY_CURRENT_USER",
                                           "Software\\GnuPG",
                                           "Install Directory");
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
    for (const QByteArray &line : lines)
        if (line.startsWith(which) && line[qstrlen(which)] == ':') {
            const int begin = qstrlen(which) + 1;
            int end = line.size();
            while (end && (line[end - 1] == '\n' || line[end - 1] == '\r')) {
                --end;
            }
            const QString result = QDir::fromNativeSeparators(QFile::decodeName(hexdecode(line.mid(begin, end - begin))));
            qCDebug(LIBKLEO_LOG) << "gpgConfListDir: found " << qPrintable(result)
                                   << " for '" << which << "'entry";
            return result;
        }
    qCDebug(LIBKLEO_LOG) << "gpgConfListDir(): didn't find '" << which << "'"
                           << "entry in output:\n" << gpgConf.readAllStandardError().constData();
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

    return !std::lexicographical_compare(std::begin(actual_version), std::end(actual_version),
                                         std::begin(minimum_version), std::end(minimum_version));

}

bool Kleo::engineIsVersion(int major, int minor, int patch, GpgME::Engine engine)
{
    static QMap<Engine, std::array<int, 3> > cachedVersions;
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

        qCDebug(LIBKLEO_LOG) << "Parsed" << actual << "as: "
                               << actual_version[0] << '.'
                               << actual_version[1] << '.'
                               << actual_version[2] << '.';
        if (!ok) {
            return false;
        }
        cachedVersions.insert(engine, actual_version);
    } else {
        actual_version = cachedVersions.value(engine);
    }

    // return ! ( actual_version < required_version )
    return !std::lexicographical_compare(std::begin(actual_version), std::end(actual_version),
                                         std::begin(required_version), std::end(required_version));
}

const QString& Kleo::paperKeyInstallPath()
{
    static const QString pkPath = QStandardPaths::findExecutable(QStringLiteral("paperkey"), QStringList() << QCoreApplication::applicationDirPath()).isEmpty() ?
                                  QStandardPaths::findExecutable(QStringLiteral("paperkey")) :
                                  QStandardPaths::findExecutable(QStringLiteral("paperkey"), QStringList() << QCoreApplication::applicationDirPath());
    return pkPath;
}

bool Kleo::haveKeyserverConfigured()
{
    if (engineIsVersion(2, 1, 19)) {
        // since 2.1.19 there is a builtin keyserver
        return true;
    }
    const QGpgME::CryptoConfig *const config = QGpgME::cryptoConfig();
    if (!config) {
        return false;
    }
    const QGpgME::CryptoConfigEntry *const entry = Kleo::getCryptoConfigEntry(config, "gpg", "keyserver");
    return entry && !entry->stringValue().isEmpty();
}

bool Kleo::gpgComplianceP(const char *mode)
{
    const auto conf = QGpgME::cryptoConfig();
    const auto entry = getCryptoConfigEntry(conf, "gpg", "compliance");
    return entry && entry->stringValue() == QString::fromLatin1(mode);
}

enum GpgME::UserID::Validity Kleo::keyValidity(const GpgME::Key &key)
{
    enum UserID::Validity validity = UserID::Validity::Unknown;

    for (const auto &uid: key.userIDs()) {
        if (validity == UserID::Validity::Unknown
            || validity > uid.validity()) {
            validity = uid.validity();
        }
    }

    return validity;
}

#ifdef Q_OS_WIN
static QString fromEncoding (unsigned int src_encoding, const char *data)
{
    int n = MultiByteToWideChar(src_encoding, 0, data, -1, NULL, 0);
    if (n < 0) {
        return QString();
    }

    wchar_t *result = (wchar_t *) malloc ((n+1) * sizeof *result);

    n = MultiByteToWideChar(src_encoding, 0, data, -1, result, n);
    if (n < 0) {
        free(result);
        return QString();
    }
    const auto ret = QString::fromWCharArray(result, n);
    free(result);
    return ret;
}
#endif

QString Kleo::stringFromGpgOutput(const QByteArray &ba)
{
#ifdef Q_OS_WIN
    /* Qt on Windows uses GetACP while GnuPG prefers
     * GetConsoleOutputCP.
     *
     * As we are not a console application GetConsoleOutputCP
     * usually returns 0.
     * From experience the closest thing that let's us guess
     * what GetConsoleOutputCP returns for a console application
     * it appears to be the OEMCP.
     */
    unsigned int cpno = GetConsoleOutputCP ();
    if (!cpno) {
        cpno = GetOEMCP();
    }
    if (!cpno) {
        cpno = GetACP();
    }
    if (!cpno) {
        qCDebug(LIBKLEO_LOG) << "Failed to find native codepage";
        return QString();
    }

    return fromEncoding(cpno, ba.constData());
#else
    return QString::fromLocal8Bit(ba);
#endif
}
