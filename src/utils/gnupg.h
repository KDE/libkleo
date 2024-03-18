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
KLEO_EXPORT QString gnupgInstallPath();
KLEO_EXPORT const QString &paperKeyInstallPath();

/**
 * Verify \p filePath using gpgv. If \p sigPath is provided it uses
 * this signature, otherwise it adds .sig to the \p filePath. If
 * \p keyring is provided that is the keyring where the signature is
 * checked against. Otherwise it uses the default of gpgv.
 * \p additionalSearchPaths can be used to specify where gpgv is
 * searched for first.
 *
 * Blocks until the verification is done which can be indefinetly to
 * allow for very large files.
 *
 * Returns true if the verification was successful, false if any problem
 * occured. */
KLEO_EXPORT bool gpgvVerify(const QString &filePath, const QString &sigPath = {}, const QString &keyring = {}, const QStringList &additionalSearchPaths = {});

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
 *
 *  Since GnuPG 2.2.42/2.4.4 dirmngr supports the special value "none"
 *  to disable usage of the default keyserver. If this value is configured
 *  and GnuPG is new enough then this function returns false.
 *  Since version 2.1.19 GnuPG has a builtin default keyserver, so that this
 *  function always returns true (unless the above applies).
 *  For older versions of GnuPG it checks if a keyserver has been configured.
 */
KLEO_EXPORT bool haveKeyserverConfigured();

/** Returns the configured keyserver or an empty string if no keyserver is
 *  configured. The special value "none" indicates that no keyserver shall
 *  be used.
 *
 *  Note: Since GnuPG 2.1.19 gpg/dirmngr uses a default keyserver if no
 *        keyserver is configured.
 *        Since GnuPG 2.2.42/2.4.4 dirmngr supports the special value "none"
 *        to disable usage of the default keyserver.
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

enum LaunchGpgAgentOptions {
    CheckForRunningAgent,
    SkipCheckForRunningAgent,
};

/** Launch the GnuPG agent if it is not already running. */
KLEO_EXPORT void launchGpgAgent(LaunchGpgAgentOptions options = CheckForRunningAgent);

/** Shut down all GnuPG daemons and restart the GnuPG agent. */
KLEO_EXPORT void restartGpgAgent();

/**
 * Returns a static list of the available algorithms.
 */
KLEO_EXPORT const std::vector<std::string> &availableAlgorithms();

/**
 * Returns a static list of the preferred algorithms with decreasing preference.
 */
KLEO_EXPORT const std::vector<std::string> &preferredAlgorithms();

/**
 * Returns a static list of algorithms that are explicitly not supported.
 */
KLEO_EXPORT const std::vector<std::string> &ignoredAlgorithms();
}
