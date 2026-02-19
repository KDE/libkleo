/*
    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <sstream>

namespace GpgME
{
class Key;
}
namespace QGpgME
{
class CryptoConfig;
class CryptoConfigEntry;
}

namespace Kleo
{

KLEO_EXPORT QGpgME::CryptoConfigEntry *getCryptoConfigEntry(const QGpgME::CryptoConfig *config, const char *componentName, const char *entryName);

/**
 * Returns true, if the key has a certification subkey.
 * Compatibility function for GpgME::Key::hasCertify() added in GpgME 1.23
 */
KLEO_EXPORT bool keyHasCertify(const GpgME::Key &key);
/**
 * Returns true, if the key has a signing subkey.
 * Compatibility function for GpgME::Key::hasSign() added in GpgME 1.23
 */
KLEO_EXPORT bool keyHasSign(const GpgME::Key &key);
/**
 * Returns true, if the key has an encryption subkey.
 * Compatibility function for GpgME::Key::hasEncrypt() added in GpgME 1.23
 */
KLEO_EXPORT bool keyHasEncrypt(const GpgME::Key &key);
/**
 * Returns true, if the key has an authentication subkey.
 * Compatibility function for GpgME::Key::hasAuthenticate() added in GpgME 1.23
 */
KLEO_EXPORT bool keyHasAuthenticate(const GpgME::Key &key);
}
