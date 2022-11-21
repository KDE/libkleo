/* -*- mode: c++; c-basic-offset:4 -*-
    utils/gnupg.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2020-2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QStringList>

#include <gpgme++/engineinfo.h>
#include <gpgme++/key.h>

class QString;
class QByteArray;

namespace Kleo
{

KLEO_EXPORT QString gnupgHomeDirectory();
KLEO_EXPORT QString gnupgPrivateKeysDirectory();

KLEO_EXPORT QString gpgConfPath();
KLEO_EXPORT QString gpgSmPath();
KLEO_EXPORT QString gpgPath();

KLEO_EXPORT QString gpgConfListDir(const char *which);
KLEO_EXPORT QString gpg4winInstallPath();
// Returns the version number.
KLEO_EXPORT QString gpg4winVersionNumber();
// Returns the version number with an optional product specific prefix.
KLEO_EXPORT QString gpg4winVersion();
KLEO_EXPORT bool gpg4winSignedversion();
KLEO_EXPORT QString gpg4winDescription();
KLEO_EXPORT QString gpg4winLongDescription();
KLEO_EXPORT QString gnupgInstallPath();
KLEO_EXPORT const QString &paperKeyInstallPath();

KLEO_EXPORT QString brandingWindowTitle();
KLEO_EXPORT QString brandingIcon();

/**
 * Returns a list of filename globs of files in one of the whitelisted folders
 * to watch for changes.
 * \sa gnupgFolderWhitelist, Kleo::FileSystemWatcher
 */
KLEO_EXPORT QStringList gnupgFileWhitelist();
/**
 * Returns a list of absolute paths of folders to watch for changes.
 * \sa gnupgFileWhitelist, Kleo::FileSystemWatcher
 */
KLEO_EXPORT QStringList gnupgFolderWhitelist();
KLEO_EXPORT int makeGnuPGError(int code);

KLEO_EXPORT bool engineIsVersion(int major, int minor, int patch, GpgME::Engine = GpgME::GpgConfEngine);

/** Returns true, if GnuPG knows which keyserver to use for keyserver
 *  operations.
 *  Since version 2.1.19 GnuPG has a builtin default keyserver, so that this
 *  function always returns true. For older versions of GnuPG it checks if
 *  a keyserver has been configured.
 */
KLEO_EXPORT bool haveKeyserverConfigured();

/** Returns the configured keyserver or an empty string if no keyserver is
 *  configured.
 *  Note: Since GnuPG 2.1.19 gpg/dirmngr uses a default keyserver if no
 *        keyserver is configured.
 */
KLEO_EXPORT QString keyserver();

/** Returns true, if GnuPG knows which server to use for directory service
 *  operations for X.509 certificates.
 */
KLEO_EXPORT bool haveX509DirectoryServerConfigured();

/* Use gnupgUsesDeVsCompliance() or gnupgIsDeVsCompliant() instead. */
KLEO_DEPRECATED_EXPORT bool gpgComplianceP(const char *mode);

/**
 * Use Kleo::DeVSCompliance::isActive() instead.
 */
KLEO_DEPRECATED_EXPORT bool gnupgUsesDeVsCompliance();

/**
 * Use Kleo::DeVSCompliance::isCompliant() instead.
 */
KLEO_DEPRECATED_EXPORT bool gnupgIsDeVsCompliant();

KLEO_EXPORT enum GpgME::UserID::Validity keyValidity(const GpgME::Key &key);

/* Convert GnuPG output to a QString with proper encoding.
 * Takes Gpg Quirks into account and might handle future
 * changes in GnuPG Output. */
KLEO_EXPORT QString stringFromGpgOutput(const QByteArray &ba);

/* Check if a minimum version is there. Strings should be in the format:
 * 1.2.3 */
KLEO_EXPORT bool versionIsAtLeast(const char *minimum, const char *actual);

/** Returns a list of component names (e.g. GnuPG, libgcrypt) followed by
 *  version numbers. This is meant for displaying in the About dialog.
 */
KLEO_EXPORT QStringList backendVersionInfo();

/** Launch the GnuPG agent if it is not already running. */
KLEO_EXPORT void launchGpgAgent();

/** Shut down all GnuPG daemons. They will be restarted automatically when
 *  needed.
 */
KLEO_EXPORT void killDaemons();

}
