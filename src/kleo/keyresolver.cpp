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

#include <config-libkleo.h>

#include "keyresolver.h"

#include "keyresolvercore.h"

#include <libkleo/formatting.h>
#include <libkleo/keycache.h>
#include <libkleo/keygroup.h>
#include <libkleo/newkeyapprovaldialog.h>

#include <libkleo_debug.h>

#include <gpgme++/key.h>

using namespace Kleo;
using namespace GpgME;

class KeyResolver::Private
{
public:
    Private(KeyResolver *qq, bool enc, bool sig, Protocol fmt, bool allowMixed)
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
        mCore.setAllowMixedProtocols(allowMixed);
    }

    ~Private() = default;

    KeyResolver::Solution expandUnresolvedGroups(KeyResolver::Solution solution);
    void showApprovalDialog(KeyResolverCore::Result result, QWidget *parent);
    void dialogAccepted();

    KeyResolver *const q;
    KeyResolverCore mCore;
    Solution mResult;

    Protocol mFormat;
    bool mEncrypt;
    bool mSign;
    bool mAllowMixed;
    // The cache is needed as a member variable to avoid rebuilding
    // it between calls if we are the only user.
    std::shared_ptr<const KeyCache> mCache;
    std::unique_ptr<NewKeyApprovalDialog> mDialog;
    Qt::WindowFlags mDialogWindowFlags;
    Protocol mPreferredProtocol;
};

static bool lessThan(const Key &leftKey, const Key &rightKey)
{
    // shouldn't happen, but still put null keys at the end
    if (leftKey.isNull()) {
        return false;
    }
    if (rightKey.isNull()) {
        return true;
    }

    // first sort by the displayed name and/or email address
    const auto leftNameAndOrEmail = Formatting::nameAndEmailForSummaryLine(leftKey);
    const auto rightNameAndOrEmail = Formatting::nameAndEmailForSummaryLine(rightKey);
    const int cmp = QString::localeAwareCompare(leftNameAndOrEmail, rightNameAndOrEmail);
    if (cmp) {
        return cmp < 0;
    }

    // sort certificates with identical name/email address by their fingerprints
    return strcmp(leftKey.primaryFingerprint(), rightKey.primaryFingerprint()) < 0;
}

KeyResolver::Solution KeyResolver::Private::expandUnresolvedGroups(KeyResolver::Solution solution)
{
    for (auto it = solution.encryptionKeys.begin(); it != solution.encryptionKeys.end(); ++it) {
        const auto &address = it.key();
        if (!it.value().empty()) {
            continue;
        }
        const auto keyMatchingAddress = mCache->findBestByMailBox(address.toUtf8().constData(), solution.protocol, KeyCache::KeyUsage::Encrypt);
        if (!keyMatchingAddress.isNull()) {
            continue;
        }
        const auto groupMatchingAddress = mCache->findGroup(address, solution.protocol, KeyCache::KeyUsage::Encrypt);
        if (!groupMatchingAddress.isNull()) {
            qCDebug(LIBKLEO_LOG) << __func__ << "Expanding unresolved" << address << "with matching group";
            const auto &groupKeys = groupMatchingAddress.keys();
            std::vector<Key> keys;
            keys.reserve(groupKeys.size());
            std::copy(groupKeys.begin(), groupKeys.end(), std::back_inserter(keys));
            std::sort(keys.begin(), keys.end(), lessThan);
            it.value() = keys;
        }
    }

    return solution;
}

void KeyResolver::Private::showApprovalDialog(KeyResolverCore::Result result, QWidget *parent)
{
    const auto preferredSolution = expandUnresolvedGroups(std::move(result.solution));
    const auto alternativeSolution = expandUnresolvedGroups(std::move(result.alternative));

    const QString sender = mCore.normalizedSender();
    mDialog = std::make_unique<NewKeyApprovalDialog>(mEncrypt,
                                                     mSign,
                                                     sender,
                                                     std::move(preferredSolution),
                                                     std::move(alternativeSolution),
                                                     mAllowMixed,
                                                     mFormat,
                                                     parent,
                                                     mDialogWindowFlags);
    connect(mDialog.get(), &QDialog::accepted, q, [this]() {
        dialogAccepted();
    });
    connect(mDialog.get(), &QDialog::rejected, q, [this]() {
        Q_EMIT q->keysResolved(false, false);
    });
    mDialog->open();
}

void KeyResolver::Private::dialogAccepted()
{
    mResult = mDialog->result();
    Q_EMIT q->keysResolved(true, false);
}

void KeyResolver::start(bool showApproval, QWidget *parentWidget)
{
    qCDebug(LIBKLEO_LOG) << "Starting ";
    if (!d->mSign && !d->mEncrypt) {
        // nothing to do
        return Q_EMIT keysResolved(true, true);
    }
    const auto result = d->mCore.resolve();
    const bool success = (result.flags & KeyResolverCore::AllResolved);
    if (success && !showApproval) {
        d->mResult = std::move(result.solution);
        Q_EMIT keysResolved(true, false);
        return;
    } else if (success) {
        qCDebug(LIBKLEO_LOG) << "No need for the user showing approval anyway.";
    }

    d->showApprovalDialog(std::move(result), parentWidget);
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

void KeyResolver::setOverrideKeys(const QMap<Protocol, QMap<QString, QStringList>> &overrides)
{
    d->mCore.setOverrideKeys(overrides);
}

void KeyResolver::setSigningKeys(const QStringList &fingerprints)
{
    d->mCore.setSigningKeys(fingerprints);
}

KeyResolver::Solution KeyResolver::result() const
{
    return d->mResult;
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

#include "moc_keyresolver.cpp"
