/*
    utils/keyhelpers.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "keyhelpers.h"

#include <libkleo/keycache.h>

#include <gpgme++/key.h>

using namespace Kleo;

namespace
{
bool havePublicKeyForSignature(const GpgME::UserID::Signature &signature)
{
    // GnuPG returns status "NoPublicKey" for missing signing keys, but also
    // for expired or revoked signing keys.
    return (signature.status() != GpgME::UserID::Signature::NoPublicKey) //
        || !KeyCache::instance()->findByKeyIDOrFingerprint(signature.signerKeyID()).isNull();
}

auto _getMissingSignerKeyIds(const std::vector<GpgME::UserID::Signature> &signatures)
{
    return std::accumulate(std::begin(signatures), std::end(signatures), std::set<QString>{}, [](auto &keyIds, const auto &signature) {
        if (!havePublicKeyForSignature(signature)) {
            keyIds.insert(QLatin1String{signature.signerKeyID()});
        }
        return keyIds;
    });
}
}

std::set<QString> Kleo::getMissingSignerKeyIds(const std::vector<GpgME::UserID> &userIds)
{
    return std::accumulate(std::begin(userIds), std::end(userIds), std::set<QString>{}, [](auto &keyIds, const auto &userID) {
        if (!userID.isBad()) {
            const auto newKeyIds = _getMissingSignerKeyIds(userID.signatures());
            std::copy(std::begin(newKeyIds), std::end(newKeyIds), std::inserter(keyIds, std::end(keyIds)));
        }
        return keyIds;
    });
}

std::set<QString> Kleo::getMissingSignerKeyIds(const std::vector<GpgME::Key> &keys)
{
    return std::accumulate(std::begin(keys), std::end(keys), std::set<QString>{}, [](auto &keyIds, const auto &key) {
        if (!key.isBad()) {
            const auto newKeyIds = getMissingSignerKeyIds(key.userIDs());
            std::copy(std::begin(newKeyIds), std::end(newKeyIds), std::inserter(keyIds, std::end(keyIds)));
        }
        return keyIds;
    });
}
