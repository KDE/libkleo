/*  -*- c++ -*-
    kleo/keyresolvercore.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2018 Intevation GmbH
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    Based on kpgp.cpp
    SPDX-FileCopyrightText: 2001, 2002 the KPGP authors
    See file libkdenetwork/AUTHORS.kpgp for details

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "keyresolvercore.h"

#include "kleo/enum.h"
#include "kleo/keygroup.h"
#include "models/keycache.h"
#include "utils/formatting.h"

#include <gpgme++/key.h>

#include "libkleo_debug.h"

using namespace Kleo;
using namespace GpgME;

namespace {

QDebug operator<<(QDebug debug, const GpgME::Key &key)
{
    if (key.isNull()) {
        debug << "Null";
    } else {
        debug << Formatting::summaryLine(key);
    }
    return debug.maybeSpace();
}

static inline bool ValidEncryptionKey(const Key &key)
{
    if (key.isNull() || key.isRevoked() || key.isExpired() ||
        key.isDisabled() || !key.canEncrypt()) {
        return false;
    }
    return true;
}

static inline bool ValidSigningKey(const Key &key)
{
    if (key.isNull() || key.isRevoked() || key.isExpired() ||
        key.isDisabled() || !key.canSign() || !key.hasSecret()) {
        return false;
    }
    return true;
}

static int keyValidity(const Key &key, const QString &address)
{
    // returns the validity of the UID matching the address or, if no UID matches, the maximal validity of all UIDs
    int overallValidity = UserID::Validity::Unknown;
    for (const auto &uid: key.userIDs()) {
        if (QString::fromStdString(uid.addrSpec()).toLower() == address.toLower()) {
            return uid.validity();
        }
        overallValidity = std::max(overallValidity, static_cast<int>(uid.validity()));
    }
    return overallValidity;
}

static int minimumValidity(const std::vector<Key> &keys, const QString &address)
{
    const int minValidity = std::accumulate(keys.cbegin(), keys.cend(), UserID::Ultimate + 1,
                                            [address] (int validity, const Key &key) {
                                                return std::min<int>(validity, keyValidity(key, address));
                                            });
    return minValidity <= UserID::Ultimate ? static_cast<UserID::Validity>(minValidity) : UserID::Unknown;
}

bool allKeysHaveProtocol(const std::vector<Key> &keys, Protocol protocol)
{
    return std::all_of(keys.cbegin(), keys.cend(), [protocol] (const Key &key) { return key.protocol() == protocol; });
}

bool anyKeyHasProtocol(const std::vector<Key> &keys, Protocol protocol)
{
    return std::any_of(std::begin(keys), std::end(keys), [protocol] (const Key &key) { return key.protocol() == protocol; });
}

} // namespace

class KeyResolverCore::Private
{
public:
    Private(KeyResolverCore* qq, bool enc, bool sig, Protocol fmt)
        : q(qq)
        , mFormat(fmt)
        , mEncrypt(enc)
        , mSign(sig)
        , mCache(KeyCache::instance())
        , mPreferredProtocol(UnknownProtocol)
        , mMinimumValidity(UserID::Marginal)
        , mCompliance(Formatting::complianceMode())
    {
    }

    ~Private() = default;

    bool isAcceptableSigningKey(const Key &key);
    bool isAcceptableEncryptionKey(const Key &key, const QString &address = QString());
    void setSender(const QString &address);
    void addRecipients(const QStringList &addresses);
    void setOverrideKeys(const QMap<Protocol, QMap<QString, QStringList>> &overrides);
    void resolveOverrides();
    std::vector<Key> resolveRecipientWithGroup(const QString &address, Protocol protocol);
    void resolveEncryptionGroups();
    std::vector<Key> resolveSenderWithGroup(const QString &address, Protocol protocol);
    void resolveSigningGroups();
    void resolveSign(Protocol proto);
    void setSigningKeys(const QStringList &fingerprints);
    std::vector<Key> resolveRecipient(const QString &address, Protocol protocol);
    void resolveEnc(Protocol proto);
    void mergeEncryptionKeys();
    Result resolve();

    KeyResolverCore *const q;
    QString mSender;
    QStringList mRecipients;
    QMap<Protocol, std::vector<Key>> mSigKeys;
    QMap<QString, QMap<Protocol, std::vector<Key>>> mEncKeys;
    QMap<QString, QMap<Protocol, QStringList>> mOverrides;

    Protocol mFormat;
    QStringList mFatalErrors;
    bool mEncrypt;
    bool mSign;
    // The cache is needed as a member variable to avoid rebuilding
    // it between calls if we are the only user.
    std::shared_ptr<const KeyCache> mCache;
    bool mAllowMixed = true;
    Protocol mPreferredProtocol;
    int mMinimumValidity;
    QString mCompliance;
};

bool KeyResolverCore::Private::isAcceptableSigningKey(const Key &key)
{
    if (!ValidSigningKey(key)) {
        return false;
    }
    if (mCompliance == QLatin1String("de-vs")) {
        if (!Formatting::isKeyDeVs(key)) {
            qCDebug(LIBKLEO_LOG) << "Rejected sig key" << key.primaryFingerprint()
                                    << "because it is not de-vs compliant.";
            return false;
        }
    }
    return true;
}

bool KeyResolverCore::Private::isAcceptableEncryptionKey(const Key &key, const QString &address)
{
    if (!ValidEncryptionKey(key)) {
        return false;
    }

    if (mCompliance == QLatin1String("de-vs")) {
        if (!Formatting::isKeyDeVs(key)) {
            qCDebug(LIBKLEO_LOG) << "Rejected enc key" << key.primaryFingerprint()
                                    << "because it is not de-vs compliant.";
            return false;
        }
    }

    if (address.isEmpty()) {
        return true;
    }
    for (const auto &uid: key.userIDs()) {
        if (uid.addrSpec() == address.toStdString()) {
            if (uid.validity() >= mMinimumValidity) {
                return true;
            }
        }
    }
    return false;
}

void KeyResolverCore::Private::setSender(const QString &address)
{
    const auto normalized = UserID::addrSpecFromString (address.toUtf8().constData());
    if (normalized.empty()) {
        // should not happen bug in the caller, non localized
        // error for bug reporting.
        mFatalErrors << QStringLiteral("The sender address '%1' could not be extracted").arg(address);
        return;
    }
    const auto normStr = QString::fromUtf8(normalized.c_str());
    mSender = normStr;
    addRecipients({address});
}

void KeyResolverCore::Private::addRecipients(const QStringList &addresses)
{
    if (!mEncrypt) {
        return;
    }

    // Internally we work with normalized addresses. Normalization
    // matches the gnupg one.
    for (const auto &addr: addresses) {
        // PGP Uids are defined to be UTF-8 (RFC 4880 §5.11)
        const auto normalized = UserID::addrSpecFromString (addr.toUtf8().constData());
        if (normalized.empty()) {
            // should not happen bug in the caller, non localized
            // error for bug reporting.
            mFatalErrors << QStringLiteral("The mail address for '%1' could not be extracted").arg(addr);
            continue;
        }
        const QString normStr = QString::fromUtf8(normalized.c_str());

        mRecipients << normStr;

        // Initially add empty lists of keys for both protocols
        mEncKeys[normStr] = {{CMS, {}}, {OpenPGP, {}}};
    }
}

void KeyResolverCore::Private::setOverrideKeys(const QMap<Protocol, QMap<QString, QStringList>> &overrides)
{
    for (auto protocolIt = overrides.cbegin(); protocolIt != overrides.cend(); ++protocolIt) {
        const Protocol &protocol = protocolIt.key();
        const auto &addressFingerprintMap = protocolIt.value();
        for (auto addressIt = addressFingerprintMap.cbegin(); addressIt != addressFingerprintMap.cend(); ++addressIt) {
            const QString &address = addressIt.key();
            const QStringList &fingerprints = addressIt.value();
            const QString normalizedAddress = QString::fromUtf8(UserID::addrSpecFromString(address.toUtf8().constData()).c_str());
            mOverrides[normalizedAddress][protocol] = fingerprints;
        }
    }
}

namespace
{
std::vector<Key> resolveOverride(const QString &address, Protocol protocol, const QStringList &fingerprints)
{
    std::vector<Key> keys;
    for (const auto &fprOrId: fingerprints) {
        const Key key = KeyCache::instance()->findByKeyIDOrFingerprint(fprOrId.toUtf8().constData());
        if (key.isNull()) {
            // FIXME: Report to caller
            qCDebug (LIBKLEO_LOG) << "Failed to find override key for:" << address << "fpr:" << fprOrId;
            continue;
        }
        if (protocol != UnknownProtocol && key.protocol() != protocol) {
            qCDebug(LIBKLEO_LOG) << "Ignoring key" << Formatting::summaryLine(key) << "given as" << Formatting::displayName(protocol) << "override for"
                                 << address;
            continue;
        }
        qCDebug(LIBKLEO_LOG) << "Using key" << Formatting::summaryLine(key) << "as" << Formatting::displayName(protocol) << "override for" << address;
        keys.push_back(key);
    }
    return keys;
}
}

void KeyResolverCore::Private::resolveOverrides()
{
    if (!mEncrypt) {
        // No encryption we are done.
        return;
    }
    for (auto addressIt = mOverrides.cbegin(); addressIt != mOverrides.cend(); ++addressIt) {
        const QString &address = addressIt.key();
        const auto &protocolFingerprintsMap = addressIt.value();

        if (!mRecipients.contains(address)) {
            qCDebug(LIBKLEO_LOG) << "Overrides provided for an address that is "
                "neither sender nor recipient. Address:" << address;
            continue;
        }

        const QStringList commonOverride = protocolFingerprintsMap.value(UnknownProtocol);
        if (!commonOverride.empty()) {
            mEncKeys[address][UnknownProtocol] = resolveOverride(address, UnknownProtocol, commonOverride);
            if (protocolFingerprintsMap.contains(OpenPGP)) {
                qCDebug(LIBKLEO_LOG) << "Ignoring OpenPGP-specific override for" << address << "in favor of common override";
            }
            if (protocolFingerprintsMap.contains(CMS)) {
                qCDebug(LIBKLEO_LOG) << "Ignoring S/MIME-specific override for" << address << "in favor of common override";
            }
        } else {
            if (mFormat != CMS) {
                mEncKeys[address][OpenPGP] = resolveOverride(address, OpenPGP, protocolFingerprintsMap.value(OpenPGP));
            }
            if (mFormat != OpenPGP) {
                mEncKeys[address][CMS] = resolveOverride(address, CMS, protocolFingerprintsMap.value(CMS));
            }
        }
    }
}

std::vector<Key> KeyResolverCore::Private::resolveSenderWithGroup(const QString &address, Protocol protocol)
{
    // prefer single-protocol groups over mixed-protocol groups
    auto group = mCache->findGroup(address, protocol, KeyUsage::Sign);
    if (group.isNull()) {
        group = mCache->findGroup(address, UnknownProtocol, KeyUsage::Sign);
    }
    if (group.isNull()) {
        return {};
    }

    // take the first key matching the protocol
    const auto &keys = group.keys();
    const auto it = std::find_if(std::begin(keys), std::end(keys), [protocol] (const auto &key) { return key.protocol() == protocol; });
    if (it == std::end(keys)) {
        qCDebug(LIBKLEO_LOG) << "group" << group.name() << "has no" << Formatting::displayName(protocol) << "signing key";
        return {};
    }
    const auto key = *it;
    if (!isAcceptableSigningKey(key)) {
        qCDebug(LIBKLEO_LOG) << "group" << group.name() << "has unacceptable signing key" << key;
        return {};
    }
    return {key};
}

void KeyResolverCore::Private::resolveSigningGroups()
{
    auto &protocolKeysMap = mSigKeys;
    if (!protocolKeysMap[UnknownProtocol].empty()) {
        // already resolved by common override
        return;
    }
    if (mFormat == OpenPGP) {
        if (!protocolKeysMap[OpenPGP].empty()) {
            // already resolved by override
            return;
        }
        protocolKeysMap[OpenPGP] = resolveSenderWithGroup(mSender, OpenPGP);
    } else if (mFormat == CMS) {
        if (!protocolKeysMap[CMS].empty()) {
            // already resolved by override
            return;
        }
        protocolKeysMap[CMS] = resolveSenderWithGroup(mSender, CMS);
    } else {
        protocolKeysMap[OpenPGP] = resolveSenderWithGroup(mSender, OpenPGP);
        protocolKeysMap[CMS] = resolveSenderWithGroup(mSender, CMS);
    }
}

void KeyResolverCore::Private::resolveSign(Protocol proto)
{
    if (!mSigKeys[proto].empty()) {
        // Explicitly set
        return;
    }
    const auto key = mCache->findBestByMailBox(mSender.toUtf8().constData(), proto, KeyUsage::Sign);
    if (key.isNull()) {
        qCDebug(LIBKLEO_LOG) << "Failed to find" << Formatting::displayName(proto) << "signing key for" << mSender;
        return;
    }
    if (!isAcceptableSigningKey(key)) {
        qCDebug(LIBKLEO_LOG) << "Unacceptable signing key" << key.primaryFingerprint() << "for" << mSender;
        return;
    }
    mSigKeys.insert(proto, {key});
}

void KeyResolverCore::Private::setSigningKeys(const QStringList &fingerprints)
{
    if (mSign) {
        for (const auto &fpr: fingerprints) {
            const auto key = mCache->findByKeyIDOrFingerprint(fpr.toUtf8().constData());
            if (key.isNull()) {
                qCDebug(LIBKLEO_LOG) << "Failed to find signing key with fingerprint" << fpr;
                continue;
            }
            mSigKeys[key.protocol()].push_back(key);
        }
    }
}

std::vector<Key> KeyResolverCore::Private::resolveRecipientWithGroup(const QString &address, Protocol protocol)
{
    const auto group = mCache->findGroup(address, protocol, KeyUsage::Encrypt);
    if (group.isNull()) {
        return {};
    }

    // If we have one unacceptable group key we reject the
    // whole group to avoid the situation where one key is
    // skipped or the operation fails.
    //
    // We are in Autoresolve land here. In the GUI we
    // will also show unacceptable group keys so that the
    // user can see which key is not acceptable.
    const auto &keys = group.keys();
    const bool allKeysAreAcceptable =
        std::all_of(std::begin(keys), std::end(keys), [this] (const auto &key) { return isAcceptableEncryptionKey(key); });
    if (!allKeysAreAcceptable) {
        qCDebug(LIBKLEO_LOG) << "group" << group.name() << "has at least one unacceptable key";
        return {};
    }
    for (const auto &k: keys) {
        qCDebug(LIBKLEO_LOG) << "Resolved encrypt to" << address << "with key" << k.primaryFingerprint();
    }
    std::vector<Key> result;
    std::copy(std::begin(keys), std::end(keys), std::back_inserter(result));
    return result;
}

void KeyResolverCore::Private::resolveEncryptionGroups()
{
    for (auto it = mEncKeys.begin(); it != mEncKeys.end(); ++it) {
        const QString &address = it.key();
        auto &protocolKeysMap = it.value();
        if (!protocolKeysMap[UnknownProtocol].empty()) {
            // already resolved by common override
            continue;
        }
        if (mFormat == OpenPGP) {
            if (!protocolKeysMap[OpenPGP].empty()) {
                // already resolved by override
                continue;
            }
            protocolKeysMap[OpenPGP] = resolveRecipientWithGroup(address, OpenPGP);
        } else if (mFormat == CMS) {
            if (!protocolKeysMap[CMS].empty()) {
                // already resolved by override
                continue;
            }
            protocolKeysMap[CMS] = resolveRecipientWithGroup(address, CMS);
        } else {
            // prefer single-protocol groups over mixed-protocol groups
            const auto openPGPGroupKeys = resolveRecipientWithGroup(address, OpenPGP);
            const auto smimeGroupKeys = resolveRecipientWithGroup(address, CMS);
            if (!openPGPGroupKeys.empty() && !smimeGroupKeys.empty()) {
                protocolKeysMap[OpenPGP] = openPGPGroupKeys;
                protocolKeysMap[CMS] = smimeGroupKeys;
            } else if (openPGPGroupKeys.empty() && smimeGroupKeys.empty()) {
                // no single-protocol groups found;
                // if mixed protocols are allowed, then look for any group with encryption keys
                if (mAllowMixed) {
                    protocolKeysMap[UnknownProtocol] = resolveRecipientWithGroup(address, UnknownProtocol);
                }
            } else {
                // there is a single-protocol group only for one protocol; use this group for all protocols
                protocolKeysMap[UnknownProtocol] = !openPGPGroupKeys.empty() ? openPGPGroupKeys : smimeGroupKeys;
            }
        }
    }
}

std::vector<Key> KeyResolverCore::Private::resolveRecipient(const QString &address, Protocol protocol)
{
    const auto key = mCache->findBestByMailBox(address.toUtf8().constData(), protocol, KeyUsage::Encrypt);
    if (key.isNull()) {
        qCDebug(LIBKLEO_LOG) << "Failed to find any" << Formatting::displayName(protocol) << "key for:" << address;
        return {};
    }
    if (!isAcceptableEncryptionKey(key, address)) {
        qCDebug(LIBKLEO_LOG) << "key for:" << address << key.primaryFingerprint()
                             << "has not enough validity";
        return {};
    }
    qCDebug(LIBKLEO_LOG) << "Resolved encrypt to" << address << "with key" << key.primaryFingerprint();
    return {key};
}

// Try to find matching keys in the provided protocol for the unresolved addresses
void KeyResolverCore::Private::resolveEnc(Protocol proto)
{
    for (auto it = mEncKeys.begin(); it != mEncKeys.end(); ++it) {
        const QString &address = it.key();
        auto &protocolKeysMap = it.value();
        if (!protocolKeysMap[proto].empty()) {
            // already resolved for current protocol (by override or group)
            continue;
        }
        const std::vector<Key> &commonOverrideOrGroup = protocolKeysMap[UnknownProtocol];
        if (!commonOverrideOrGroup.empty()) {
            // there is a common override or group; use it for current protocol if possible
            if (allKeysHaveProtocol(commonOverrideOrGroup, proto)) {
                protocolKeysMap[proto] = commonOverrideOrGroup;
                continue;
            } else {
                qCDebug(LIBKLEO_LOG) << "Common override/group for" << address << "is unusable for" << Formatting::displayName(proto);
                continue;
            }
        }
        protocolKeysMap[proto] = resolveRecipient(address, proto);
    }
}

auto getBestEncryptionKeys(const QMap<QString, QMap<Protocol, std::vector<Key>>> &encryptionKeys, Protocol preferredProtocol)
{
    QMap<QString, std::vector<Key>> result;

    for (auto it = encryptionKeys.begin(); it != encryptionKeys.end(); ++it) {
        const QString &address = it.key();
        auto &protocolKeysMap = it.value();
        const std::vector<Key> &overrideKeys = protocolKeysMap[UnknownProtocol];
        if (!overrideKeys.empty()) {
            result.insert(address, overrideKeys);
            continue;
        }
        const std::vector<Key> &keysOpenPGP = protocolKeysMap[OpenPGP];
        const std::vector<Key> &keysCMS = protocolKeysMap[CMS];
        if (keysOpenPGP.empty() && keysCMS.empty()) {
            result.insert(address, {});
        } else if (!keysOpenPGP.empty() && keysCMS.empty()) {
            result.insert(address, keysOpenPGP);
        } else if (keysOpenPGP.empty() && !keysCMS.empty()) {
            result.insert(address, keysCMS);
        } else {
            // check whether OpenPGP keys or S/MIME keys have higher validity
            const int validityPGP = minimumValidity(keysOpenPGP, address);
            const int validityCMS = minimumValidity(keysCMS, address);
            if ((validityCMS > validityPGP) || (validityCMS == validityPGP && preferredProtocol == CMS)) {
                result.insert(address, keysCMS);
            } else {
                result.insert(address, keysOpenPGP);
            }
        }
    }

    return result;
}

namespace
{
bool hasUnresolvedRecipients(const QMap<QString, QMap<Protocol, std::vector<Key>>> &encryptionKeys, Protocol protocol)
{
    return std::any_of(std::cbegin(encryptionKeys), std::cend(encryptionKeys),
                       [protocol] (const auto &protocolKeysMap) {
                           return protocolKeysMap.value(protocol).empty();
                       });
}

bool anyCommonOverrideHasKeyOfType(const QMap<QString, QMap<Protocol, std::vector<Key>>> &encryptionKeys, Protocol protocol)
{
    return std::any_of(std::cbegin(encryptionKeys), std::cend(encryptionKeys),
                       [protocol] (const auto &protocolKeysMap) {
                           return anyKeyHasProtocol(protocolKeysMap.value(UnknownProtocol), protocol);
                       });
}

auto keysForProtocol(const QMap<QString, QMap<Protocol, std::vector<Key>>> &encryptionKeys, Protocol protocol)
{
    QMap<QString, std::vector<Key>> keys;
    for (auto it = std::begin(encryptionKeys), end = std::end(encryptionKeys); it != end; ++it) {
        const QString &address = it.key();
        const auto &protocolKeysMap = it.value();
        keys.insert(address, protocolKeysMap.value(protocol));
    }
    return keys;
}

template<typename T>
auto concatenate(std::vector<T> v1, const std::vector<T> &v2)
{
    v1.reserve(v1.size() + v2.size());
    v1.insert(std::end(v1), std::begin(v2), std::end(v2));
    return v1;
}

}

KeyResolverCore::Result KeyResolverCore::Private::resolve()
{
    qCDebug(LIBKLEO_LOG) << "Starting ";
    if (!mSign && !mEncrypt) {
        // nothing to do
        return {AllResolved, {}, {}};
    }

    // First resolve through overrides
    resolveOverrides();

    // check protocols needed for overrides
    const bool commonOverridesNeedOpenPGP = anyCommonOverrideHasKeyOfType(mEncKeys, OpenPGP);
    const bool commonOverridesNeedCMS = anyCommonOverrideHasKeyOfType(mEncKeys, CMS);
    if ((mFormat == OpenPGP && commonOverridesNeedCMS)
            || (mFormat == CMS && commonOverridesNeedOpenPGP)
            || (!mAllowMixed && commonOverridesNeedOpenPGP && commonOverridesNeedCMS)) {
        // invalid protocol requirements -> clear intermediate result and abort resolution
        mEncKeys.clear();
        return {Error, {}, {}};
    }

    // Next look for matching groups of keys
    if (mSign) {
        resolveSigningGroups();
    }
    if (mEncrypt) {
        resolveEncryptionGroups();
    }

    // Then look for signing / encryption keys
    if (mFormat == OpenPGP || mFormat == UnknownProtocol) {
        resolveSign(OpenPGP);
        resolveEnc(OpenPGP);
    }
    const bool pgpOnly = (!mEncrypt || !hasUnresolvedRecipients(mEncKeys, OpenPGP)) && (!mSign || mSigKeys.contains(OpenPGP));

    if (mFormat == OpenPGP) {
        return {
            SolutionFlags((pgpOnly ? AllResolved : SomeUnresolved) | OpenPGPOnly),
            {OpenPGP, mSigKeys.value(OpenPGP), keysForProtocol(mEncKeys, OpenPGP)},
            {}
        };
    }

    if (mFormat == CMS || mFormat == UnknownProtocol) {
        resolveSign(CMS);
        resolveEnc(CMS);
    }
    const bool cmsOnly = (!mEncrypt || !hasUnresolvedRecipients(mEncKeys, CMS)) && (!mSign || mSigKeys.contains(CMS));

    if (mFormat == CMS) {
        return {
            SolutionFlags((cmsOnly ? AllResolved : SomeUnresolved) | CMSOnly),
            {CMS, mSigKeys.value(CMS), keysForProtocol(mEncKeys, CMS)},
            {}
        };
    }

    // check if single-protocol solution has been found
    if (cmsOnly && (!pgpOnly || mPreferredProtocol == CMS)) {
        if (!mAllowMixed) {
            return {
                SolutionFlags(AllResolved | CMSOnly),
                {CMS, mSigKeys.value(CMS), keysForProtocol(mEncKeys, CMS)},
                {OpenPGP, mSigKeys.value(OpenPGP), keysForProtocol(mEncKeys, OpenPGP)}
            };
        } else {
            return {
                SolutionFlags(AllResolved | CMSOnly),
                {CMS, mSigKeys.value(CMS), keysForProtocol(mEncKeys, CMS)},
                {}
            };
        }
    }
    if (pgpOnly) {
        if (!mAllowMixed) {
            return {
                SolutionFlags(AllResolved | OpenPGPOnly),
                {OpenPGP, mSigKeys.value(OpenPGP), keysForProtocol(mEncKeys, OpenPGP)},
                {CMS, mSigKeys.value(CMS), keysForProtocol(mEncKeys, CMS)}
            };
        } else {
            return {
                SolutionFlags(AllResolved | OpenPGPOnly),
                {OpenPGP, mSigKeys.value(OpenPGP), keysForProtocol(mEncKeys, OpenPGP)},
                {}
            };
        }
    }

    if (!mAllowMixed) {
        // return incomplete single-protocol solution
        if (mPreferredProtocol == CMS) {
            return {
                SolutionFlags(SomeUnresolved | CMSOnly),
                {CMS, mSigKeys.value(CMS), keysForProtocol(mEncKeys, CMS)},
                {OpenPGP, mSigKeys.value(OpenPGP), keysForProtocol(mEncKeys, OpenPGP)}
            };
        } else {
            return {
                SolutionFlags(SomeUnresolved | OpenPGPOnly),
                {OpenPGP, mSigKeys.value(OpenPGP), keysForProtocol(mEncKeys, OpenPGP)},
                {CMS, mSigKeys.value(CMS), keysForProtocol(mEncKeys, CMS)}
            };
        }
    }

    const auto bestEncryptionKeys = getBestEncryptionKeys(mEncKeys, mPreferredProtocol);
    const bool allAddressesAreResolved = std::all_of(std::begin(bestEncryptionKeys), std::end(bestEncryptionKeys),
                                                     [] (const auto &keys) { return !keys.empty(); });
    if (allAddressesAreResolved) {
        return {
            SolutionFlags(AllResolved | MixedProtocols),
            {UnknownProtocol, concatenate(mSigKeys.value(OpenPGP), mSigKeys.value(CMS)), bestEncryptionKeys},
            {}
        };
    }

    const bool allKeysAreOpenPGP = std::all_of(std::begin(bestEncryptionKeys), std::end(bestEncryptionKeys),
                                               [] (const auto &keys) { return allKeysHaveProtocol(keys, OpenPGP); });
    if (allKeysAreOpenPGP) {
        return {
            SolutionFlags(SomeUnresolved | OpenPGPOnly),
            {OpenPGP, mSigKeys.value(OpenPGP), bestEncryptionKeys},
            {}
        };
    }

    const bool allKeysAreCMS = std::all_of(std::begin(bestEncryptionKeys), std::end(bestEncryptionKeys),
                                           [] (const auto &keys) { return allKeysHaveProtocol(keys, CMS); });
    if (allKeysAreCMS) {
        return {
            SolutionFlags(SomeUnresolved | CMSOnly),
            {CMS, mSigKeys.value(CMS), bestEncryptionKeys},
            {}
        };
    }

    return {
        SolutionFlags(SomeUnresolved | MixedProtocols),
        {UnknownProtocol, concatenate(mSigKeys.value(OpenPGP), mSigKeys.value(CMS)), bestEncryptionKeys},
        {}
    };
}

KeyResolverCore::KeyResolverCore(bool encrypt, bool sign, Protocol fmt)
    : d(new Private(this, encrypt, sign, fmt))
{
}

KeyResolverCore::~KeyResolverCore() = default;

void KeyResolverCore::setSender(const QString &address)
{
    d->setSender(address);
}

QString KeyResolverCore::normalizedSender() const
{
    return d->mSender;
}

void KeyResolverCore::setRecipients(const QStringList &addresses)
{
    d->addRecipients(addresses);
}

void KeyResolverCore::setSigningKeys(const QStringList &fingerprints)
{
    d->setSigningKeys(fingerprints);
}

void KeyResolverCore::setOverrideKeys(const QMap<Protocol, QMap<QString, QStringList>> &overrides)
{
    d->setOverrideKeys(overrides);
}

void KeyResolverCore::setAllowMixedProtocols(bool allowMixed)
{
    d->mAllowMixed = allowMixed;
}

void KeyResolverCore::setPreferredProtocol(Protocol proto)
{
    d->mPreferredProtocol = proto;
}

void KeyResolverCore::setMinimumValidity(int validity)
{
    d->mMinimumValidity = validity;
}

KeyResolverCore::Result KeyResolverCore::resolve()
{
    return d->resolve();
}
