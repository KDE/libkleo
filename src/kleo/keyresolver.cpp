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
        mCore.setAllowMixedProtocols(allowMixed);
    }

    ~Private() = default;

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

void KeyResolver::Private::showApprovalDialog(KeyResolverCore::Result result, QWidget *parent)
{
    const QString sender = mCore.normalizedSender();
    mDialog = std::make_unique<NewKeyApprovalDialog>(mEncrypt,
                                                     mSign,
                                                     sender,
                                                     std::move(result.solution),
                                                     std::move(result.alternative),
                                                     mAllowMixed,
                                                     mFormat,
                                                     parent,
                                                     mDialogWindowFlags);
    connect (mDialog.get(), &QDialog::accepted, q, [this] () {
        dialogAccepted();
    });
    connect (mDialog.get(), &QDialog::rejected, q, [this] () {
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

void KeyResolver::setOverrideKeys(const QMap<Protocol, QMap<QString, QStringList> > &overrides)
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
