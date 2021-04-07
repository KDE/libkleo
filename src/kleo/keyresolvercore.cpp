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

#include "models/keycache.h"
#include "utils/formatting.h"

#include <gpgme++/key.h>

#include "libkleo_debug.h"

using namespace Kleo;
using namespace GpgME;

namespace {

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
    void resolveSign(Protocol proto);
    void setSigningKeys(const QStringList &fingerprints);
    std::vector<Key> resolveRecipient(const QString &address, Protocol protocol);
    void resolveEnc(Protocol proto);
    void mergeEncryptionKeys();
    QStringList unresolvedRecipients(GpgME::Protocol protocol) const;
    bool resolve();

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
    if (mSign) {
        mSender = normStr;
    }
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

void KeyResolverCore::Private::resolveSign(Protocol proto)
{
    if (mSigKeys.contains(proto)) {
        // Explicitly set
        return;
    }
    const auto keys = mCache->findBestByMailBox(mSender.toUtf8().constData(),
                                                proto, true, false);
    for (const auto &key: keys) {
        if (key.isNull()) {
            continue;
        }
        if (!isAcceptableSigningKey(key)) {
            qCDebug(LIBKLEO_LOG) << "Unacceptable signing key" << key.primaryFingerprint()
                                    << "for" << mSender;
            return;
        }
    }

    if (!keys.empty() && !keys[0].isNull()) {
        mSigKeys.insert(proto, keys);
    }
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
            auto list = mSigKeys.value(key.protocol());
            list.push_back(key);
            mSigKeys.insert(key.protocol(), list);
        }
    }
}

std::vector<Key> KeyResolverCore::Private::resolveRecipient(const QString &address, Protocol protocol)
{
    const auto keys = mCache->findBestByMailBox(address.toUtf8().constData(), protocol, false, true);
    if (keys.empty() || keys[0].isNull()) {
        qCDebug(LIBKLEO_LOG) << "Failed to find any" << Formatting::displayName(protocol) << "key for: " << address;
        return {};
    }
    if (keys.size() == 1) {
        if (!isAcceptableEncryptionKey(keys[0], address)) {
            qCDebug(LIBKLEO_LOG) << "key for:" << address << keys[0].primaryFingerprint()
                                    << "has not enough validity";
            return {};
        }
    } else {
        // If we have one unacceptable group key we reject the
        // whole group to avoid the situation where one key is
        // skipped or the operation fails.
        //
        // We are in Autoresolve land here. In the GUI we
        // will also show unacceptable group keys so that the
        // user can see which key is not acceptable.
        bool unacceptable = false;
        for (const auto &key: keys) {
            if (!isAcceptableEncryptionKey(key)) {
                qCDebug(LIBKLEO_LOG) << "group key for:" << address << keys[0].primaryFingerprint()
                                        << "has not enough validity";
                unacceptable = true;
                break;
            }
        }
        if (unacceptable) {
            return {};
        }
    }
    for (const auto &k: keys) {
        qCDebug(LIBKLEO_LOG) << "Resolved encrypt to" << address << "with key" << k.primaryFingerprint();
    }
    return keys;
}

// Try to find matching keys in the provided protocol for the unresolved addresses
void KeyResolverCore::Private::resolveEnc(Protocol proto)
{
    for (auto it = mEncKeys.begin(); it != mEncKeys.end(); ++it) {
        const QString &address = it.key();
        auto &protocolKeysMap = it.value();
        if (!protocolKeysMap[proto].empty()) {
            // already resolved for current protocol (by override)
            continue;
        }
        const std::vector<Key> &commonOverride = protocolKeysMap[UnknownProtocol];
        if (!commonOverride.empty()) {
            // there is a common override; use it for current protocol if possible
            if (allKeysHaveProtocol(commonOverride, proto)) {
                protocolKeysMap[proto] = commonOverride;
                continue;
            } else {
                qCDebug(LIBKLEO_LOG) << "Common override for" << address << "is unusable for" << Formatting::displayName(proto);
                continue;
            }
        }
        protocolKeysMap[proto] = resolveRecipient(address, proto);
    }
}

void KeyResolverCore::Private::mergeEncryptionKeys()
{
    for (auto it = mEncKeys.begin(); it != mEncKeys.end(); ++it) {
        const QString &address = it.key();
        auto &protocolKeysMap = it.value();
        if (!protocolKeysMap[UnknownProtocol].empty()) {
            // override keys are set for address
            continue;
        }
        const std::vector<Key> &keysOpenPGP = protocolKeysMap.value(OpenPGP);
        const std::vector<Key> &keysCMS = protocolKeysMap.value(CMS);
        if (keysOpenPGP.empty() && keysCMS.empty()) {
            continue;
        } else if (!keysOpenPGP.empty() && keysCMS.empty()) {
            protocolKeysMap[UnknownProtocol] = keysOpenPGP;
        } else if (keysOpenPGP.empty() && !keysCMS.empty()) {
            protocolKeysMap[UnknownProtocol] = keysCMS;
        } else {
            // check whether OpenPGP keys or S/MIME keys have higher validity
            const int validityPGP = minimumValidity(keysOpenPGP, address);
            const int validityCMS = minimumValidity(keysCMS, address);
            if ((validityPGP > validityCMS)
                || (validityPGP == validityCMS && mPreferredProtocol == OpenPGP)) {
                protocolKeysMap[UnknownProtocol] = keysOpenPGP;
            } else if ((validityCMS > validityPGP)
                || (validityCMS == validityPGP && mPreferredProtocol == CMS)) {
                protocolKeysMap[UnknownProtocol] = keysCMS;
            } else {
                protocolKeysMap[UnknownProtocol] = keysOpenPGP;
            }
        }
    }
}

QStringList KeyResolverCore::Private::unresolvedRecipients(GpgME::Protocol protocol) const
{
    QStringList result;
    result.reserve(mEncKeys.size());
    for (auto it = mEncKeys.begin(); it != mEncKeys.end(); ++it) {
        const auto &protocolKeysMap = it.value();
        if (protocolKeysMap.value(protocol).empty()) {
            result.push_back(it.key());
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
}

bool KeyResolverCore::Private::resolve()
{
    qCDebug(LIBKLEO_LOG) << "Starting ";
    if (!mSign && !mEncrypt) {
        // nothing to do
        return true;
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
        return false;
    }

    // Then look for signing / encryption keys
    if (mFormat != CMS) {
        resolveSign(OpenPGP);
        resolveEnc(OpenPGP);
    }
    const bool pgpOnly = !hasUnresolvedRecipients(mEncKeys, OpenPGP) && (!mSign || mSigKeys.contains(OpenPGP));

    if (mFormat != OpenPGP) {
        resolveSign(CMS);
        resolveEnc(CMS);
    }
    const bool cmsOnly = !hasUnresolvedRecipients(mEncKeys, CMS) && (!mSign || mSigKeys.contains(CMS));

    if (mAllowMixed && mFormat == UnknownProtocol) {
        mergeEncryptionKeys();
    }
    const bool hasUnresolvedMerged = mAllowMixed && mFormat == UnknownProtocol && hasUnresolvedRecipients(mEncKeys, UnknownProtocol);

    // Check if we need the user to select different keys.
    bool needsUser = false;
    if (!pgpOnly && !cmsOnly) {
        if (mAllowMixed && mFormat == UnknownProtocol) {
            needsUser = hasUnresolvedMerged;
        } else {
            needsUser = (mFormat == UnknownProtocol)
                        || (mFormat == OpenPGP && !pgpOnly)
                        || (mFormat == CMS && !cmsOnly);
        }
        if (mSign) {
            // So every recipient could be resolved through
            // a combination of PGP and S/MIME do we also
            // have signing keys for both?
            needsUser |= !(mSigKeys.contains(OpenPGP) &&
                           mSigKeys.contains(CMS));
        }
    }

    if (!needsUser) {
        if (pgpOnly && cmsOnly) {
            if (mPreferredProtocol == CMS) {
                mSigKeys.remove(OpenPGP);
                for (auto &protocolKeysMap: mEncKeys) {
                    protocolKeysMap.remove(OpenPGP);
                }
            } else {
                mSigKeys.remove(CMS);
                for (auto &protocolKeysMap: mEncKeys) {
                    protocolKeysMap.remove(CMS);
                }
            }
        } else if (pgpOnly) {
            mSigKeys.remove(CMS);
            for (auto &protocolKeysMap: mEncKeys) {
                protocolKeysMap.remove(CMS);
            }
        } else if (cmsOnly) {
            mSigKeys.remove(OpenPGP);
            for (auto &protocolKeysMap: mEncKeys) {
                protocolKeysMap.remove(OpenPGP);
            }
        }

        qCDebug(LIBKLEO_LOG) << "Automatic key resolution done.";
        return true;
    }

    return false;
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

bool KeyResolverCore::resolve()
{
    return d->resolve();
}

QMap <Protocol, std::vector<Key> > KeyResolverCore::signingKeys() const
{
    return d->mSigKeys;
}

QMap<Protocol, QMap<QString, std::vector<Key>>> KeyResolverCore::encryptionKeys() const
{
    QMap<Protocol, QMap<QString, std::vector<Key>>> result;

    for (auto addressIt = d->mEncKeys.cbegin(); addressIt != d->mEncKeys.cend(); ++addressIt) {
        const QString &address = addressIt.key();
        const auto &protocolKeysMap = addressIt.value();
        for (auto protocolIt = protocolKeysMap.cbegin(); protocolIt != protocolKeysMap.cend(); ++protocolIt) {
            const Protocol protocol = protocolIt.key();
            const auto &keys = protocolIt.value();
            if (!keys.empty()) {
                result[protocol][address] = keys;
            }
        }
    }

    return result;
}

QStringList KeyResolverCore::unresolvedRecipients(GpgME::Protocol protocol) const
{
    return d->unresolvedRecipients(protocol);
}
