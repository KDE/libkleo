/*
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

/** Returns true if \p signature is a self-signature. */
KLEO_EXPORT bool isSelfSignature(const GpgME::UserID::Signature &signature);

/**
 * Returns true if the most recent self-signature of \p userId is a revocation
 * signature or if it has expired.
 */
KLEO_EXPORT bool isRevokedOrExpired(const GpgME::UserID &userId);

/** Returns true if the most recent self-signature of \p userId has expired. */
KLEO_EXPORT bool isExpired(const GpgME::UserID &userId);

/**
 * Returns true if \p key can be used to certify user IDs, i.e. if the key
 * has the required capability and if the secret key of the (primary)
 * certification subkey is available in the keyring or on a smart card.
 */
KLEO_EXPORT bool canCreateCertifications(const GpgME::Key &key);

/**
 * Returns true if the key \p key can be certified, i.e. it is an OpenPGP key
 * which is neither revoked nor expired and which has at least one user ID
 * that is neither revoked nor expired.
 */
KLEO_EXPORT bool canBeCertified(const GpgME::Key &key);

/**
 * Returns true if the certificate \p key can be used for encryption, i.e. if
 * it has at least one encryption subkey that is neither expired nor revoked
 * nor otherwise invalid.
 */
KLEO_EXPORT bool canBeUsedForEncryption(const GpgME::Key &key);

/**
 * Returns true if the certificate \p key can be used for signing data, i.e. if
 * it has at least one signing subkey that is neither expired nor revoked
 * nor otherwise invalid and for which the secret key is available.
 */
KLEO_EXPORT bool canBeUsedForSigning(const GpgME::Key &key);

/**
 * Returns true if \p key can be used for operations requiring the secret key,
 * i.e. if the secret key of the primary key pair is available in the keyring
 * or on a smart card.
 *
 * \note Key::hasSecret() also returns true if a secret key stub, e.g. of an
 * offline key, is available in the keyring.
 */
KLEO_EXPORT bool canBeUsedForSecretKeyOperations(const GpgME::Key &key);

/**
 * Returns true if \p userId can be revoked, i.e. if it isn't the last valid
 * user ID of an OpenPGP key.
 */
KLEO_EXPORT bool canRevokeUserID(const GpgME::UserID &userId);

/**
 * Returns true if the secret key of the primary key pair of \p key is stored
 * in the keyring.
 */
KLEO_EXPORT bool isSecretKeyStoredInKeyRing(const GpgME::Key &key);

/**
 * Returns true if any keys suitable for certifying user IDs are available in
 * the keyring or on a smart card.
 *
 * \sa canCreateCertifications
 */
KLEO_EXPORT bool userHasCertificationKey();

enum CertificationRevocationFeasibility {
    CertificationCanBeRevoked = 0,
    CertificationNotMadeWithOwnKey,
    CertificationIsSelfSignature,
    CertificationIsRevocation,
    CertificationIsExpired,
    CertificationIsInvalid,
    CertificationKeyNotAvailable,
};

/**
 * Checks if the user can revoke the given \p certification.
 */
KLEO_EXPORT CertificationRevocationFeasibility userCanRevokeCertification(const GpgME::UserID::Signature &certification);

/**
 * Returns true if the user can revoke any of the certifications of the \p userId.
 *
 * \sa userCanRevokeCertification
 */
KLEO_EXPORT bool userCanRevokeCertifications(const GpgME::UserID &userId);

/**
 * Returns true, if the user ID \p userID belongs to the key \p key.
 */
KLEO_EXPORT bool userIDBelongsToKey(const GpgME::UserID &userID, const GpgME::Key &key);

/**
 * Returns a unary predicate to check if a user ID belongs to the key \p key.
 */
inline auto userIDBelongsToKey(const GpgME::Key &key)
{
    return [key](const GpgME::UserID &userID) {
        return userIDBelongsToKey(userID, key);
    };
}

/**
 * Returns true, if the two user IDs \p lhs and \p rhs are equal.
 *
 * Equality means that both user IDs belong to the same key, contain identical
 * text, and have the same creation date (i.e. the creation date of the first
 * self-signature is the same).
 */
KLEO_EXPORT bool userIDsAreEqual(const GpgME::UserID &lhs, const GpgME::UserID &rhs);

/**
 * Returns true, if the user ID \p userId has a valid, exportable certification
 * that was made with one of the available ultimately trusted OpenPGP keys.
 */
KLEO_EXPORT bool userIDIsCertifiedByUser(const GpgME::UserID &userId);

struct KLEO_EXPORT KeysByProtocol {
    std::vector<GpgME::Key> openpgp;
    std::vector<GpgME::Key> cms;
};

/**
 * Partitions the keys \p keys into OpenPGP keys and CMS certificates.
 */
template<typename KeyContainer>
KeysByProtocol partitionKeysByProtocol(const KeyContainer &keys)
{
    KeysByProtocol result;
    std::partition_copy(std::begin(keys), std::end(keys), std::back_inserter(result.openpgp), std::back_inserter(result.cms), [](const auto &key) {
        return key.protocol() == GpgME::OpenPGP;
    });
    return result;
}

inline bool subkeyUsesCombinedAlgorithms(const GpgME::Subkey &subkey)
{
    if (const char *keygrip = subkey.keyGrip()) {
        return std::string_view{keygrip}.find(',') != std::string_view::npos;
    }
    return false;
}
}
