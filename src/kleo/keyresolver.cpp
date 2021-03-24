/*  -*- c++ -*-
    keyresolver.cpp

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

#include "keyresolver.h"

#include "keyresolvercore.h"

#include "models/keycache.h"
#include "ui/newkeyapprovaldialog.h"
#include "utils/formatting.h"

#include <gpgme++/key.h>

#include "libkleo_debug.h"

using namespace Kleo;
using namespace GpgME;

class KeyResolver::Private
{
public:
    Private(KeyResolver* qq, bool enc, bool sig, Protocol fmt, bool allowMixed)
        : q(qq)
        , mCore(enc, sig, fmt)
        , mFormat(fmt)
        , mEncrypt(enc)
        , mSign(sig)
        , mAllowMixed(allowMixed)
        , mCache(KeyCache::instance())
        , mDialogWindowFlags(Qt::WindowFlags())
        , mPreferredProtocol(UnknownProtocol)
    {
    }

    ~Private() = default;

    void showApprovalDialog(QWidget *parent);
    void dialogAccepted();

    KeyResolver *const q;
    KeyResolverCore mCore;
    QMap<Protocol, std::vector<Key>> mSigKeys;
    QMap<Protocol, QMap<QString, std::vector<Key>>> mEncKeys;

    Protocol mFormat;
    bool mEncrypt;
    bool mSign;
    bool mAllowMixed;
    // The cache is needed as a member variable to avoid rebuilding
    // it between calls if we are the only user.
    std::shared_ptr<const KeyCache> mCache;
    std::shared_ptr<NewKeyApprovalDialog> mDialog;
    Qt::WindowFlags mDialogWindowFlags;
    Protocol mPreferredProtocol;
};

void KeyResolver::Private::showApprovalDialog(QWidget *parent)
{
    const QString sender = mCore.normalizedSender();
    const QMap<GpgME::Protocol, std::vector<GpgME::Key>> signingKeys = mCore.signingKeys();
    const QStringList unresolvedPGP = mCore.unresolvedRecipients(OpenPGP);
    const QStringList unresolvedCMS = mCore.unresolvedRecipients(CMS);

    QMap<QString, std::vector<Key> > resolvedSig;
    QStringList unresolvedSig;
    const bool pgpOnly = unresolvedPGP.empty() && (!mSign || signingKeys.contains(OpenPGP));
    const bool cmsOnly = unresolvedCMS.empty() && (!mSign || signingKeys.contains(CMS));
    // First handle the signing keys
    if (mSign) {
        if (signingKeys.empty()) {
            unresolvedSig << sender;
        } else {
            std::vector<Key> resolvedSigKeys;
            for (const auto &keys: signingKeys) {
                for (const auto &key: keys) {
                    resolvedSigKeys.push_back(key);
                }
            }
            resolvedSig.insert(sender, resolvedSigKeys);
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
                for (const auto &addr: qAsConst(unresolvedPGP)) {
                    if (unresolvedCMS.contains(addr)) {
                        unresolvedRecp << addr;
                    }
                }
            } else if (mFormat == OpenPGP) {
                unresolvedRecp = unresolvedPGP;
            } else if (mFormat == CMS) {
                unresolvedRecp = unresolvedCMS;
            }
        }

        // Now Map all resolved encryption keys regardless of the format.
        const QMap<Protocol, QMap<QString, std::vector<Key>>> encryptionKeys = mCore.encryptionKeys();
        for (const auto &map: encryptionKeys.values()) {
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
                                                                                sender,
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

void KeyResolver::Private::dialogAccepted()
{
    for (const auto &key: mDialog->signingKeys()) {
        if (!mSigKeys.contains(key.protocol())) {
            mSigKeys.insert(key.protocol(), std::vector<Key>());
        }
        mSigKeys[key.protocol()].push_back(key);
    }

    const auto &encMap = mDialog->encryptionKeys();
    // First we fill the protocol-specific maps with
    // the results of the dialog. Then we use the sender
    // address to determine if a keys in the specific
    // maps need updating.

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

void KeyResolver::start(bool showApproval, QWidget *parentWidget)
{
    qCDebug(LIBKLEO_LOG) << "Starting ";
    if (!d->mSign && !d->mEncrypt) {
        // nothing to do
        return Q_EMIT keysResolved(true, true);
    }
    const bool success = d->mCore.resolve();

    if (success && !showApproval) {
        Q_EMIT keysResolved(true, false);
        return;
    } else if (success) {
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
    d->mCore.setRecipients(addresses);
}

void KeyResolver::setSender(const QString &address)
{
    d->mCore.setSender(address);
}

void KeyResolver::setOverrideKeys(const QMap<Protocol, QMap<QString, QStringList> > &overrides)
{
    d->mCore.setOverrideKeys(overrides);
}

void KeyResolver::setSigningKeys(const QStringList &fingerprints)
{
    d->mCore.setSigningKeys(fingerprints);
}

QMap <Protocol, QMap<QString, std::vector<Key> > > KeyResolver::encryptionKeys() const
{
    return d->mCore.encryptionKeys();
}

QMap <Protocol, std::vector<Key> > KeyResolver::signingKeys() const
{
    return d->mCore.signingKeys();
}

void KeyResolver::setDialogWindowFlags(Qt::WindowFlags flags)
{
    d->mDialogWindowFlags = flags;
}

void KeyResolver::setPreferredProtocol(Protocol proto)
{
    d->mCore.setPreferredProtocol(proto);
}

void KeyResolver::setMinimumValidity(int validity)
{
    d->mCore.setMinimumValidity(validity);
}
