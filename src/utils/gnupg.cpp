/* -*- mode: c++; c-basic-offset:4 -*-
    utils/gnupg.cpp

    This file is part of Kleopatra, the KDE keymanager
    Copyright (c) 2008 Klarälvdalens Datakonsult AB
    2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH

    Kleopatra is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kleopatra is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    In addition, as a special exception, the copyright holders give
    permission to link the code of this program with any edition of
    the Qt library by Trolltech AS, Norway (or with modified versions
    of Qt that use the same license as Qt), and distribute linked
    combinations including the two.  You must obey the GNU General
    Public License in all respects for all of the code used other than
    Qt.  If you modify this file, you may extend this exception to
    your version of the file, but you are not obligated to do so.  If
    you do not wish to do so, delete this exception statement from
    your version.
*/

#include "gnupg.h"

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

using namespace GpgME;

QString Kleo::gnupgHomeDirectory()
{
#ifdef Q_OS_WIN
    return QFile::decodeName(default_homedir());
#else
    const QByteArray gnupgHome = qgetenv("GNUPGHOME");
    if (!gnupgHome.isEmpty()) {
        return QFile::decodeName(gnupgHome);
    } else {
        return QDir::homePath() + QLatin1String("/.gnupg");
    }
#endif
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

QString Kleo::gpg4winVersion()
{
    QFile versionFile(gpg4winInstallPath() + QStringLiteral("/../VERSION"));
    if (!versionFile.open(QIODevice::ReadOnly)) {
        // No need to translate this should only be the case in development
        // builds.
        return QStringLiteral("Unknown (no VERSION file found)");
    }
    const QString g4wTag = QString::fromUtf8(versionFile.readLine());
    if (!g4wTag.startsWith(QLatin1String("gpg4win"))) {
        // Hu? Something unknown
        return QStringLiteral("Unknown (invalid VERSION file found)");
    }
    // Next line is version.
    return QString::fromUtf8(versionFile.readLine()).trimmed();
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
    QRegExp rx(QLatin1String("(\\d+)\\.(\\d+)\\.(\\d+)(?:-svn\\d+)?.*"));
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
    const QGpgME::CryptoConfigEntry *const entry = config->entry(QStringLiteral("gpg"), QStringLiteral("Keyserver"), QStringLiteral("keyserver"));
    return entry && !entry->stringValue().isEmpty();
}

bool Kleo::gpgComplianceP(const char *mode)
{
    const auto conf = QGpgME::cryptoConfig();
    const auto entry = conf->entry(QStringLiteral("gpg"),
                                   QStringLiteral("Configuration"),
                                   QStringLiteral("compliance"));

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
