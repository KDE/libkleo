/*
    utils/keyhelpers.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "keyhelpers.h"

#include <libkleo/algorithm.h>
#include <libkleo/compat.h>
#include <libkleo/keycache.h>

#include <libkleo_debug.h>

#include <QDate>

// needed for GPGME_VERSION_NUMBER
#include <gpgme.h>

#include <algorithm>
#include <iterator>

using namespace Kleo;
using namespace GpgME;

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

bool Kleo::isRemoteKey(const GpgME::Key &key)
{
    // a remote key looked up via WKD has key list mode Local; therefore we also look for the key in the local key ring
    return (key.keyListMode() == GpgME::Extern) || KeyCache::instance()->findByFingerprint(key.primaryFingerprint()).isNull();
}

GpgME::UserID::Validity Kleo::minimalValidityOfNotRevokedUserIDs(const Key &key)
{
    const std::vector<UserID> userIDs = key.userIDs();
    const int minValidity = std::accumulate(userIDs.begin(), userIDs.end(), UserID::Ultimate + 1, [](int validity, const UserID &userID) {
        return userID.isRevoked() ? validity : std::min(validity, static_cast<int>(userID.validity()));
    });
    return minValidity <= UserID::Ultimate ? static_cast<UserID::Validity>(minValidity) : UserID::Unknown;
}

GpgME::UserID::Validity Kleo::maximalValidityOfUserIDs(const Key &key)
{
    const auto userIDs = key.userIDs();
    const int maxValidity = std::accumulate(userIDs.begin(), userIDs.end(), 0, [](int validity, const UserID &userID) {
        return std::max(validity, static_cast<int>(userID.validity()));
    });
    return static_cast<UserID::Validity>(maxValidity);
}

bool Kleo::allUserIDsHaveFullValidity(const GpgME::Key &key)
{
    return minimalValidityOfNotRevokedUserIDs(key) >= UserID::Full;
}

namespace
{
bool isLastValidUserID(const GpgME::UserID &userId)
{
    if (Kleo::isRevokedOrExpired(userId)) {
        return false;
    }
    const auto userIds = userId.parent().userIDs();
    const int numberOfValidUserIds = std::count_if(std::begin(userIds), std::end(userIds), [](const auto &u) {
        return !Kleo::isRevokedOrExpired(u);
    });
    return numberOfValidUserIds == 1;
}

bool hasValidUserID(const GpgME::Key &key)
{
    return Kleo::any_of(key.userIDs(), [](const auto &u) {
        return !Kleo::isRevokedOrExpired(u);
    });
}
}

bool Kleo::isSelfSignature(const GpgME::UserID::Signature &signature)
{
    return !qstrcmp(signature.parent().parent().keyID(), signature.signerKeyID());
}

bool Kleo::isRevokedOrExpired(const GpgME::UserID &userId)
{
    if (userId.isRevoked() || userId.parent().isExpired()) {
        return true;
    }
    const auto sigs = userId.signatures();
    std::vector<GpgME::UserID::Signature> selfSigs;
    std::copy_if(std::begin(sigs), std::end(sigs), std::back_inserter(selfSigs), &Kleo::isSelfSignature);
    std::sort(std::begin(selfSigs), std::end(selfSigs));
    // check the most recent signature
    const auto sig = !selfSigs.empty() ? selfSigs.back() : GpgME::UserID::Signature{};
    return !sig.isNull() && (sig.isRevokation() || sig.isExpired());
}

bool Kleo::canCreateCertifications(const GpgME::Key &key)
{
    return Kleo::keyHasCertify(key) && canBeUsedForSecretKeyOperations(key);
}

bool Kleo::canBeCertified(const GpgME::Key &key)
{
    return key.protocol() == GpgME::OpenPGP //
        && !key.isBad() //
        && hasValidUserID(key);
}

namespace
{
static inline bool subkeyHasSecret(const GpgME::Subkey &subkey)
{
#if GPGME_VERSION_NUMBER >= 0x011102 // 1.17.2
    // we need to check the primary subkey because Key::hasSecret() is also true if just the secret key stub of an offline key is available
    return subkey.isSecret();
#else
    // older versions of GpgME did not always set the secret flag for card keys
    return subkey.isSecret() || subkey.isCardKey();
#endif
}
}

bool Kleo::canBeUsedForEncryption(const GpgME::Key &key)
{
    return !key.isBad() && Kleo::any_of(key.subkeys(), [](const auto &subkey) {
        return subkey.canEncrypt() && !subkey.isBad();
    });
}

bool Kleo::canBeUsedForSigning(const GpgME::Key &key)
{
    return !key.isBad() && Kleo::any_of(key.subkeys(), [](const auto &subkey) {
        return subkey.canSign() && !subkey.isBad() && subkeyHasSecret(subkey);
    });
}

bool Kleo::canBeUsedForSecretKeyOperations(const GpgME::Key &key)
{
    return subkeyHasSecret(key.subkey(0));
}

bool Kleo::canRevokeUserID(const GpgME::UserID &userId)
{
    return (!userId.isNull() //
            && userId.parent().protocol() == GpgME::OpenPGP //
            && !isLastValidUserID(userId));
}

bool Kleo::isSecretKeyStoredInKeyRing(const GpgME::Key &key)
{
    return key.subkey(0).isSecret() && !key.subkey(0).isCardKey();
}

bool Kleo::userHasCertificationKey()
{
    const auto secretKeys = KeyCache::instance()->secretKeys();
    return Kleo::any_of(secretKeys, [](const auto &k) {
        return (k.protocol() == GpgME::OpenPGP) && canCreateCertifications(k);
    });
}

Kleo::CertificationRevocationFeasibility Kleo::userCanRevokeCertification(const GpgME::UserID::Signature &certification)
{
    const auto certificationKey = KeyCache::instance()->findByKeyIDOrFingerprint(certification.signerKeyID());
    const bool isSelfSignature = qstrcmp(certification.parent().parent().keyID(), certification.signerKeyID()) == 0;
    if (!certificationKey.hasSecret()) {
        return CertificationNotMadeWithOwnKey;
    } else if (isSelfSignature) {
        return CertificationIsSelfSignature;
    } else if (certification.isRevokation()) {
        return CertificationIsRevocation;
    } else if (certification.isExpired()) {
        return CertificationIsExpired;
    } else if (certification.isInvalid()) {
        return CertificationIsInvalid;
    } else if (!canCreateCertifications(certificationKey)) {
        return CertificationKeyNotAvailable;
    }
    return CertificationCanBeRevoked;
}

bool Kleo::userCanRevokeCertifications(const GpgME::UserID &userId)
{
    if (userId.numSignatures() == 0) {
        qCWarning(LIBKLEO_LOG) << __func__ << "- Error: Signatures of user ID" << QString::fromUtf8(userId.id()) << "not available";
    }
    return Kleo::any_of(userId.signatures(), [](const auto &certification) {
        return userCanRevokeCertification(certification) == CertificationCanBeRevoked;
    });
}

bool Kleo::userIDBelongsToKey(const GpgME::UserID &userID, const GpgME::Key &key)
{
    return !qstricmp(userID.parent().primaryFingerprint(), key.primaryFingerprint());
}

static time_t creationDate(const GpgME::UserID &uid)
{
    // returns the date of the first self-signature
    for (unsigned int i = 0, numSignatures = uid.numSignatures(); i < numSignatures; ++i) {
        const auto sig = uid.signature(i);
        if (Kleo::isSelfSignature(sig)) {
            return sig.creationTime();
        }
    }
    return 0;
}

bool Kleo::userIDsAreEqual(const GpgME::UserID &lhs, const GpgME::UserID &rhs)
{
    return (qstrcmp(lhs.parent().primaryFingerprint(), rhs.parent().primaryFingerprint()) == 0 //
            && qstrcmp(lhs.id(), rhs.id()) == 0 //
            && creationDate(lhs) == creationDate(rhs));
}

static inline bool isOpenPGPCertification(const GpgME::UserID::Signature &sig)
{
    // certification class is 0x10, ..., 0x13
    return (sig.certClass() & ~0x03) == 0x10;
}

static bool isOpenPGPCertificationByUser(const GpgME::UserID::Signature &sig)
{
    if (!isOpenPGPCertification(sig)) {
        return false;
    }
    const auto certificationKey = KeyCache::instance()->findByKeyIDOrFingerprint(sig.signerKeyID());
    return certificationKey.ownerTrust() == Key::Ultimate;
}

bool Kleo::userIDIsCertifiedByUser(const GpgME::UserID &userId)
{
    if (userId.parent().protocol() != GpgME::OpenPGP) {
        qCWarning(LIBKLEO_LOG) << __func__ << "not called with OpenPGP key";
        return false;
    }
    if (userId.numSignatures() == 0) {
        qCWarning(LIBKLEO_LOG) << __func__ << "- Error: Signatures of user ID" << QString::fromUtf8(userId.id()) << "not available";
    }
    for (unsigned int i = 0, numSignatures = userId.numSignatures(); i < numSignatures; ++i) {
        const auto sig = userId.signature(i);
        if ((sig.status() == UserID::Signature::NoError) && !sig.isBad() && sig.isExportable() && isOpenPGPCertificationByUser(sig)) {
            return true;
        }
    }
    return false;
}
