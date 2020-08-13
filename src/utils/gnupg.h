/* -*- mode: c++; c-basic-offset:4 -*-
    utils/gnupg.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2020 g10 Code GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifndef __KLEOPATRA_GNUPGHELPER_H__
#define __KLEOPATRA_GNUPGHELPER_H__

#include <gpgme++/engineinfo.h>
#include <gpgme++/key.h>

/* Support compilation with GPGME older than 1.9.  */
#include <gpgme++/gpgmepp_version.h>
#if GPGMEPP_VERSION > 0x10900
# define GPGME_HAS_KEY_IS_DEVS
#endif

/* Does the given object comply with DE_VS?  This macro can be used to
   ensure that we can still build against older versions of GPGME
   without cluttering the code with preprocessor conditionals.  */
#ifdef GPGME_HAS_KEY_IS_DEVS
# define IS_DE_VS(x)	(x).isDeVs()
#else
# define IS_DE_VS(x)	false
#endif

#include <kleo_export.h>

class QString;
class QStringList;
class QByteArray;

namespace Kleo
{

KLEO_EXPORT QString gnupgHomeDirectory();

KLEO_EXPORT QString gpgConfPath();
KLEO_EXPORT QString gpgSmPath();
KLEO_EXPORT QString gpgPath();

KLEO_EXPORT QString gpgConfListDir(const char *which);
KLEO_EXPORT QString gpg4winInstallPath();
KLEO_EXPORT QString gpg4winVersion();
KLEO_EXPORT bool gpg4winSignedversion();
KLEO_EXPORT QString gpg4winDescription();
KLEO_EXPORT QString gpg4winLongDescription();
KLEO_EXPORT QString gnupgInstallPath();
KLEO_EXPORT const QString& paperKeyInstallPath();

KLEO_EXPORT QStringList gnupgFileWhitelist();
KLEO_EXPORT int makeGnuPGError(int code);

KLEO_EXPORT bool engineIsVersion(int major, int minor, int patch, GpgME::Engine = GpgME::GpgConfEngine);
KLEO_EXPORT bool haveKeyserverConfigured();
KLEO_EXPORT bool gpgComplianceP(const char *mode);
KLEO_EXPORT enum GpgME::UserID::Validity keyValidity(const GpgME::Key &key);

/* Convert GnuPG output to a QString with proper encoding.
 * Takes Gpg Quirks into account and might handle future
 * changes in GnuPG Output. */
KLEO_EXPORT QString stringFromGpgOutput(const QByteArray &ba);

/* Check if a minimum version is there. Strings should be in the format:
 * 1.2.3 */
KLEO_EXPORT bool versionIsAtLeast(const char *minimum, const char *actual);
}

#endif // __KLEOPATRA_GNUPGHELPER_H__
