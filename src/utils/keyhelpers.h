/*
    utils/keyhelpers.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021-2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QStringList>

#include <gpgme++/key.h>

#include <algorithm>
#include <set>
#include <vector>

namespace GpgME
{
class Key;
class UserID;
}

namespace Kleo
{

template<typename KeyContainer>
QStringList getFingerprints(const KeyContainer &keys)
{
    QStringList fingerprints;

    fingerprints.reserve(keys.size());
    std::transform(std::begin(keys), std::end(keys), std::back_inserter(fingerprints), [](const auto &key) {
        return QString::fromLatin1(key.primaryFingerprint());
    });

    return fingerprints;
}

KLEO_EXPORT std::set<QString> getMissingSignerKeyIds(const std::vector<GpgME::UserID> &userIds);

KLEO_EXPORT std::set<QString> getMissingSignerKeyIds(const std::vector<GpgME::Key> &keys);

/**
 * Returns true, if the key \p key is the result of a lookup which is not present
 * in the local key ring.
 */
KLEO_EXPORT bool isRemoteKey(const GpgME::Key &key);

KLEO_EXPORT GpgME::UserID::Validity minimalValidityOfNotRevokedUserIDs(const GpgME::Key &key);

KLEO_EXPORT GpgME::UserID::Validity maximalValidityOfUserIDs(const GpgME::Key &key);

/* Is the key valid i.e. are all not revoked uids fully trusted?  */
KLEO_EXPORT bool allUserIDsHaveFullValidity(const GpgME::Key &key);

template<typename RangeOfKeys>
bool allKeysHaveProtocol(const RangeOfKeys &keys, GpgME::Protocol protocol)
{
    return std::all_of(std::begin(keys), std::end(keys), [protocol](const auto &key) {
        return key.protocol() == protocol;
    });
}

template<typename RangeOfKeys>
bool anyKeyHasProtocol(const RangeOfKeys &keys, GpgME::Protocol protocol)
{
    return std::any_of(std::begin(keys), std::end(keys), [protocol](const auto &key) {
        return key.protocol() == protocol;
    });
}
}
