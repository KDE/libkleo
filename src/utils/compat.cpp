/*
    utils/compat.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "compat.h"

#include "algorithm.h"

#include <QGpgME/CryptoConfig>

#include <gpgme++/key.h>

using namespace QGpgME;

QGpgME::CryptoConfigEntry *Kleo::getCryptoConfigEntry(const CryptoConfig *config, const char *componentName, const char *entryName)
{
    if (!config) {
        return nullptr;
    }
    return config->entry(QString::fromLatin1(componentName), QString::fromLatin1(entryName));
}

bool Kleo::keyHasCertify(const GpgME::Key &key)
{
#if GPGMEPP_KEY_HAS_HASCERTIFY_SIGN_ENCRYPT_AUTHENTICATE
    return key.hasCertify();
#else
    return Kleo::any_of(key.subkeys(), [](const auto &subkey) {
        return subkey.canCertify();
    });
#endif
}

bool Kleo::keyHasSign(const GpgME::Key &key)
{
#if GPGMEPP_KEY_HAS_HASCERTIFY_SIGN_ENCRYPT_AUTHENTICATE
    return key.hasSign();
#else
    return Kleo::any_of(key.subkeys(), [](const auto &subkey) {
        return subkey.canSign();
    });
#endif
}

bool Kleo::keyHasEncrypt(const GpgME::Key &key)
{
#if GPGMEPP_KEY_HAS_HASCERTIFY_SIGN_ENCRYPT_AUTHENTICATE
    return key.hasEncrypt();
#else
    return Kleo::any_of(key.subkeys(), [](const auto &subkey) {
        return subkey.canEncrypt();
    });
#endif
}

bool Kleo::keyHasAuthenticate(const GpgME::Key &key)
{
#if GPGMEPP_KEY_HAS_HASCERTIFY_SIGN_ENCRYPT_AUTHENTICATE
    return key.hasAuthenticate();
#else
    return Kleo::any_of(key.subkeys(), [](const auto &subkey) {
        return subkey.canAuthenticate();
    });
#endif
}
