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
    QStringList unresolvedRecipients(GpgME::Protocol protocol) const;
    bool resolve();

    KeyResolverCore *const q;
    QString mSender;
    QStringList mRecipients;
    QMap<Protocol, std::vector<Key>> mSigKeys;
    QMap<Protocol, QMap<QString, std::vector<Key>>> mEncKeys;
    QMap<Protocol, QMap<QString, QStringList>> mOverrides;

    Protocol mFormat;
    QStringList mFatalErrors;
    bool mEncrypt;
    bool mSign;
    // The cache is needed as a member variable to avoid rebuilding
    // it between calls if we are the only user.
    std::shared_ptr<const KeyCache> mCache;
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
    for (const auto &addr :addresses) {
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
        mEncKeys[CMS][normStr] = {};
        mEncKeys[OpenPGP][normStr] = {};
    }
}

void KeyResolverCore::Private::setOverrideKeys(const QMap<Protocol, QMap<QString, QStringList>> &overrides)
{
    QMap<QString, QStringList> normalizedOverrides;
    for (const auto fmt: overrides.keys()) {
        for (const auto &addr: overrides[fmt].keys()) {
            const auto normalized = QString::fromUtf8(
                    UserID::addrSpecFromString (addr.toUtf8().constData()).c_str());
            const auto fingerprints = overrides[fmt][addr];
            normalizedOverrides.insert(addr, fingerprints);
        }
        mOverrides.insert(fmt, normalizedOverrides);
    }
}

// Apply the overrides this is also where specific formats come in
void KeyResolverCore::Private::resolveOverrides()
{
    if (!mEncrypt) {
        // No encryption we are done.
        return;
    }
    for (Protocol fmt: mOverrides.keys()) {
        // Iterate over the crypto message formats
        if (mFormat != UnknownProtocol && mFormat != fmt && fmt != UnknownProtocol) {
            // Skip overrides for the wrong format
            continue;
        }
        for (const auto &addr: mOverrides[fmt].keys()) {
            // For all address overrides of this format.
            for (const auto &fprOrId: mOverrides[fmt][addr]) {
                // For all the keys configured for this address.
                const auto key = mCache->findByKeyIDOrFingerprint(fprOrId.toUtf8().constData());
                if (key.isNull()) {
                    qCDebug (LIBKLEO_LOG) << "Failed to find override key for:" << addr
                        << "fpr:" << fprOrId;
                    continue;
                }

                // Now add it to the resolved keys
                if (!mRecipients.contains(addr)) {
                    qCDebug(LIBKLEO_LOG) << "Override provided for an address that is "
                        "neither sender nor recipient. Address: " << addr;
                    continue;
                }

                Protocol resolvedFmt = fmt;
                if (fmt == UnknownProtocol) {
                    // Take the format from the key.
                    resolvedFmt = key.protocol();
                }

                auto recpMap = mEncKeys.value(resolvedFmt);
                auto keys = recpMap.value(addr);
                keys.push_back(key);
                recpMap.insert(addr, keys);
                mEncKeys.insert(resolvedFmt, recpMap);

                qCDebug(LIBKLEO_LOG) << "Override" << addr << Formatting::displayName(resolvedFmt) << fprOrId;
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
    auto encMap = mEncKeys.value(proto);
    for (auto it = encMap.begin(); it != encMap.end(); ++it) {
        if (!it.value().empty()) {
            continue;
        }
        it.value() = resolveRecipient(it.key(), proto);
    }
    mEncKeys.insert(proto, encMap);
}

QStringList KeyResolverCore::Private::unresolvedRecipients(GpgME::Protocol protocol) const
{
    QStringList result;
    const auto encMap = mEncKeys.value(protocol);
    result.reserve(encMap.size());
    for (auto it = encMap.cbegin(); it != encMap.cend(); ++it) {
        if (it.value().empty()) {
            result.push_back(it.key());
        }
    }
    return result;
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

    // Then look for signing / encryption keys
    if (mFormat != CMS) {
        resolveSign(OpenPGP);
        resolveEnc(OpenPGP);
    }
    const QStringList unresolvedPGP = unresolvedRecipients(OpenPGP);
    bool pgpOnly = unresolvedPGP.empty() && (!mSign || mSigKeys.contains(OpenPGP));

    if (mFormat != OpenPGP) {
        resolveSign(CMS);
        resolveEnc(CMS);
    }
    const QStringList unresolvedCMS = unresolvedRecipients(CMS);
    bool cmsOnly = unresolvedCMS.empty() && (!mSign || mSigKeys.contains(CMS));

    // Check if we need the user to select different keys.
    bool needsUser = false;
    if (!pgpOnly && !cmsOnly) {
        for (const auto &unresolved: unresolvedPGP) {
            if (unresolvedCMS.contains(unresolved)) {
                // We have at least one unresolvable key.
                needsUser = true;
                break;
            }
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
                mEncKeys.remove(OpenPGP);
            } else {
                mSigKeys.remove(CMS);
                mEncKeys.remove(CMS);
            }
        } else if (pgpOnly) {
            mSigKeys.remove(CMS);
            mEncKeys.remove(CMS);
        } else if (cmsOnly) {
            mSigKeys.remove(OpenPGP);
            mEncKeys.remove(OpenPGP);
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

QMap <Protocol, QMap<QString, std::vector<Key> > > KeyResolverCore::encryptionKeys() const
{
    return d->mEncKeys;
}

QStringList KeyResolverCore::unresolvedRecipients(GpgME::Protocol protocol) const
{
    return d->unresolvedRecipients(protocol);
}
