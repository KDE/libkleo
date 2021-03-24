/*  -*- c++ -*-
    keyresolver.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2018 Intevation GmbH

    Based on kpgp.cpp
    SPDX-FileCopyrightText: 2001, 2002 the KPGP authors
    See file libkdenetwork/AUTHORS.kpgp for details

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "keyresolver.h"

#include "models/keycache.h"
#include "ui/newkeyapprovaldialog.h"
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

class KeyResolver::Private
{
public:
    Private(KeyResolver* qq, bool enc, bool sig, Protocol fmt, bool allowMixed) :
            q(qq), mFormat(fmt), mEncrypt(enc), mSign(sig),
            mAllowMixed(allowMixed),
            mCache(KeyCache::instance()),
            mDialogWindowFlags(Qt::WindowFlags()),
            mPreferredProtocol(UnknownProtocol),
            mMinimumValidity(UserID::Marginal),
            mCompliance(Formatting::complianceMode())
    {
    }

    ~Private() = default;

    bool isAcceptableSigningKey(const Key &key)
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

    bool isAcceptableEncryptionKey(const Key &key, const QString &address = QString())
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

    void addRecpients (const QStringList &addresses)
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

            // Initially mark them as unresolved for both protocols
            if (!mUnresolvedCMS.contains(normStr)) {
                mUnresolvedCMS << normStr;
            }
            if (!mUnresolvedPGP.contains(normStr)) {
                mUnresolvedPGP << normStr;
            }

            mRecipients << normStr;
        }
    }

    // Apply the overrides this is also where specific formats come in
    void resolveOverrides()
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

                    // Now add it to the resolved keys and remove it from our list
                    // of unresolved keys.
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

                    // Now we can remove it from our unresolved lists.
                    if (key.protocol() == OpenPGP) {
                        mUnresolvedPGP.removeAll(addr);
                    } else {
                        mUnresolvedCMS.removeAll(addr);
                    }
                    qCDebug(LIBKLEO_LOG) << "Override" << addr << Formatting::displayName(resolvedFmt) << fprOrId;
                }
            }
        }
    }

    void resolveSign(Protocol proto)
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

    void setSigningKeys(const std::vector<Key> &keys)
    {
        if (mSign) {
            for (const auto &key: keys) {
                auto list = mSigKeys.value(key.protocol());
                list.push_back(key);
                mSigKeys.insert(key.protocol(), list);
            }
        }
    }

    // Try to find matching keys in the provided protocol for the unresolved addresses
    // only updates the any maps.
    void resolveEnc(Protocol proto)
    {
        auto encMap = mEncKeys.value(proto);
        QMutableStringListIterator it((proto == Protocol::OpenPGP) ? mUnresolvedPGP : mUnresolvedCMS);
        while (it.hasNext()) {
            const QString addr = it.next();
            const auto keys = mCache->findBestByMailBox(addr.toUtf8().constData(),
                                                        proto, false, true);
            if (keys.empty() || keys[0].isNull()) {
                qCDebug(LIBKLEO_LOG) << "Failed to find any"
                                     << (proto == Protocol::OpenPGP ? "OpenPGP" : "CMS")
                                     << "key for: " << addr;
                continue;
            }
            if (keys.size() == 1) {
                if (!isAcceptableEncryptionKey(keys[0], addr)) {
                    qCDebug(LIBKLEO_LOG) << "key for: " << addr << keys[0].primaryFingerprint()
                                         << "has not enough validity";
                    continue;
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
                        qCDebug(LIBKLEO_LOG) << "group key for: " << addr << keys[0].primaryFingerprint()
                                             << "has not enough validity";
                        unacceptable = true;
                        break;
                    }
                }
                if (unacceptable) {
                    continue;
                }
            }
            encMap.insert(addr, keys);
            for (const auto &k: keys) {
                if (!k.isNull()) {
                    qCDebug(LIBKLEO_LOG) << "Resolved encrypt to" << addr
                                            << "with key" << k.primaryFingerprint();
                }
            }
            it.remove();
        }
        mEncKeys.insert(proto, encMap);
    }

    void showApprovalDialog(QWidget *parent)
    {
        QMap<QString, std::vector<Key> > resolvedSig;
        QStringList unresolvedSig;
        bool pgpOnly = mUnresolvedPGP.empty() && (!mSign || mSigKeys.contains(OpenPGP));
        bool cmsOnly = mUnresolvedCMS.empty() && (!mSign || mSigKeys.contains(CMS));
        // First handle the signing keys
        if (mSign) {
            if (mSigKeys.empty()) {
                unresolvedSig << mSender;
            } else {
                std::vector<Key> resolvedSigKeys;
                for (const auto &keys: qAsConst(mSigKeys)) {
                    for (const auto &key: keys) {
                        resolvedSigKeys.push_back(key);
                    }
                }
                resolvedSig.insert(mSender, resolvedSigKeys);
            }
        }

        // Now build the encryption keys
        QMap<QString, std::vector<Key> > resolvedRecp;
        QStringList unresolvedRecp;

        if (mEncrypt) {
            // Use all unresolved recipients.
            if (!cmsOnly && !pgpOnly) {
                if (mFormat == UnknownProtocol) {
                    // In Auto Format we can now remove recipients that could
                    // be resolved either through CMS or PGP
                    for (const auto &addr: qAsConst(mUnresolvedPGP)) {
                        if (mUnresolvedCMS.contains(addr)) {
                            unresolvedRecp << addr;
                        }
                    }
                } else if (mFormat == OpenPGP) {
                    unresolvedRecp = mUnresolvedPGP;
                } else if (mFormat == CMS) {
                    unresolvedRecp = mUnresolvedCMS;
                }
            }

            // Now Map all resolved encryption keys regardless of the format.
            for (const auto &map: mEncKeys.values()) {
                // Foreach format
                for (const auto &addr: map.keys()) {
                    // Foreach sender
                    if (!resolvedRecp.contains(addr) || !resolvedRecp[addr].size()) {
                        resolvedRecp.insert(addr, map[addr]);
                    } else {
                        std::vector<Key> merged = resolvedRecp[addr];
                        // Add without duplication
                        for (const auto &k: map[addr]) {
                            const auto it = std::find_if (merged.begin(), merged.end(), [k] (const Key &y) {
                                return (k.primaryFingerprint() && y.primaryFingerprint() &&
                                        !strcmp (k.primaryFingerprint(), y.primaryFingerprint()));
                            });
                            if (it == merged.end()) {
                                merged.push_back(k);
                            }
                        }
                        resolvedRecp[addr] = merged;
                    }
                }
            }
        }

        // Do we force the protocol?
        Protocol forcedProto = mFormat;

        // Start with the protocol for which every keys could be found.
        Protocol presetProtocol;

        if (mPreferredProtocol == CMS && cmsOnly) {
            presetProtocol = CMS;
        } else {
            presetProtocol = pgpOnly ? OpenPGP :
                             cmsOnly ? CMS :
                             mPreferredProtocol;
        }

        mDialog = std::shared_ptr<NewKeyApprovalDialog>(new NewKeyApprovalDialog(resolvedSig,
                                                                                 resolvedRecp,
                                                                                 unresolvedSig,
                                                                                 unresolvedRecp,
                                                                                 mSender,
                                                                                 mAllowMixed,
                                                                                 forcedProto,
                                                                                 presetProtocol,
                                                                                 parent,
                                                                                 mDialogWindowFlags));
        connect (mDialog.get(), &QDialog::accepted, q, [this] () {
            dialogAccepted();
        });
        connect (mDialog.get(), &QDialog::rejected, q, [this] () {
            Q_EMIT q->keysResolved(false, false);}
        );
        mDialog->open();
    }

    void dialogAccepted()
    {
        // Update keymaps accordingly
        mSigKeys.clear();
        for (const auto &key: mDialog->signingKeys()) {
            if (!mSigKeys.contains(key.protocol())) {
                mSigKeys.insert(key.protocol(), std::vector<Key>());
            }
            mSigKeys[key.protocol()].push_back(key);
        }
        const auto &encMap = mDialog->encryptionKeys();
        // First we clear the Any Maps and fill them with
        // the results of the dialog. Then we use the sender
        // address to determine if a keys in the specific
        // maps need updating.
        mEncKeys.remove(OpenPGP);
        mEncKeys.remove(CMS);

        bool isUnresolved = false;
        for (const auto &addr: encMap.keys()) {
            for (const auto &key: encMap[addr]) {
                if (key.isNull()) {
                    isUnresolved = true;
                }
                if (!mEncKeys.contains(key.protocol())) {
                    mEncKeys.insert(key.protocol(), QMap<QString, std::vector<Key> >());
                }
                if (!mEncKeys[key.protocol()].contains(addr)) {
                    mEncKeys[key.protocol()].insert(addr, std::vector<Key>());
                }
                qCDebug (LIBKLEO_LOG) << "Adding" << addr << "for" << Formatting::displayName(key.protocol())
                                      << "fpr:" << key.primaryFingerprint();

                mEncKeys[key.protocol()][addr].push_back(key);
            }
        }

        if (isUnresolved) {
            // TODO show warning
        }

        Q_EMIT q->keysResolved(true, false);
    }

    KeyResolver *const q;
    QString mSender;
    QStringList mRecipients;
    QMap<Protocol, std::vector<Key> > mSigKeys;
    QMap<Protocol, QMap<QString, std::vector<Key> > >mEncKeys;
    QMap<Protocol, QMap<QString, QStringList> > mOverrides;

    QStringList mUnresolvedPGP, mUnresolvedCMS;

    Protocol mFormat;
    QStringList mFatalErrors;
    bool mEncrypt, mSign;
    bool mAllowMixed;
    // The cache is needed as a member variable to avoid rebuilding
    // it between calls if we are the only user.
    std::shared_ptr<const KeyCache> mCache;
    std::shared_ptr<NewKeyApprovalDialog> mDialog;
    Qt::WindowFlags mDialogWindowFlags;
    Protocol mPreferredProtocol;
    int mMinimumValidity;
    QString mCompliance;
};

void KeyResolver::start(bool showApproval, QWidget *parentWidget)
{
    qCDebug(LIBKLEO_LOG) << "Starting ";
    if (!d->mSign && !d->mEncrypt) {
        // nothing to do
        return Q_EMIT keysResolved(true, true);
    }

    // First resolve through overrides
    d->resolveOverrides();

    // Then look for signing / encryption keys
    if (d->mFormat != CMS) {
        d->resolveSign(OpenPGP);
        d->resolveEnc(OpenPGP);
    }
    bool pgpOnly = d->mUnresolvedPGP.empty() && (!d->mSign || d->mSigKeys.contains(OpenPGP));

    if (d->mFormat != OpenPGP) {
        d->resolveSign(CMS);
        d->resolveEnc(CMS);
    }
    bool cmsOnly = d->mUnresolvedCMS.empty() && (!d->mSign || d->mSigKeys.contains(CMS));

    // Check if we need the user to select different keys.
    bool needsUser = false;
    if (!pgpOnly && !cmsOnly) {
        for (const auto &unresolved: d->mUnresolvedPGP) {
            if (d->mUnresolvedCMS.contains(unresolved)) {
                // We have at least one unresolvable key.
                needsUser = true;
                break;
            }
        }
        if (d->mSign) {
            // So every recipient could be resolved through
            // a combination of PGP and S/MIME do we also
            // have signing keys for both?
            needsUser |= !(d->mSigKeys.contains(OpenPGP) &&
                           d->mSigKeys.contains(CMS));
        }
    }

    if (!needsUser && !showApproval) {
        if (pgpOnly && cmsOnly) {
            if (d->mPreferredProtocol == CMS) {
                d->mSigKeys.remove(OpenPGP);
                d->mEncKeys.remove(OpenPGP);
            } else {
                d->mSigKeys.remove(CMS);
                d->mEncKeys.remove(CMS);
            }
        } else if (pgpOnly) {
            d->mSigKeys.remove(CMS);
            d->mEncKeys.remove(CMS);
        } else if (cmsOnly) {
            d->mSigKeys.remove(OpenPGP);
            d->mEncKeys.remove(OpenPGP);
        }

        qCDebug(LIBKLEO_LOG) << "Automatic key resolution done.";
        Q_EMIT keysResolved(true, false);
        return;
    } else if (!needsUser) {
        qCDebug(LIBKLEO_LOG) << "No need for the user showing approval anyway.";
    }

    d->showApprovalDialog(parentWidget);
}

KeyResolver::KeyResolver(bool encrypt, bool sign, Protocol fmt, bool allowMixed)
    : d(new Private(this, encrypt, sign, fmt, allowMixed))
{
}

Kleo::KeyResolver::~KeyResolver() = default;

void KeyResolver::setRecipients(const QStringList &addresses)
{
    d->addRecpients(addresses);
}

void KeyResolver::setSender(const QString &address)
{
    const auto normalized = UserID::addrSpecFromString (address.toUtf8().constData());
    if (normalized.empty()) {
        // should not happen bug in the caller, non localized
        // error for bug reporting.
        d->mFatalErrors << QStringLiteral("The sender address '%1' could not be extracted").arg(address);
        return;
    }
    const auto normStr = QString::fromUtf8(normalized.c_str());
    if (d->mSign) {
        d->mSender = normStr;
    }
    d->addRecpients({address});
}

void KeyResolver::setOverrideKeys(const QMap<Protocol, QMap<QString, QStringList> > &overrides)
{
    QMap<QString, QStringList> normalizedOverrides;
    for (const auto fmt: overrides.keys()) {
        for (const auto &addr: overrides[fmt].keys()) {
            const auto normalized = QString::fromUtf8(
                    UserID::addrSpecFromString (addr.toUtf8().constData()).c_str());
            const auto fingerprints = overrides[fmt][addr];
            normalizedOverrides.insert(addr, fingerprints);
        }
        d->mOverrides.insert(fmt, normalizedOverrides);
    }
}

QMap <Protocol, QMap<QString, std::vector<Key> > > KeyResolver::encryptionKeys() const
{
    return d->mEncKeys;
}

QMap <Protocol, std::vector<Key> > KeyResolver::signingKeys() const
{
    return d->mSigKeys;
}

void KeyResolver::setDialogWindowFlags(Qt::WindowFlags flags)
{
    d->mDialogWindowFlags = flags;
}

void KeyResolver::setPreferredProtocol(Protocol proto)
{
    d->mPreferredProtocol = proto;
}

void KeyResolver::setMinimumValidity(int validity)
{
    d->mMinimumValidity = validity;
}
