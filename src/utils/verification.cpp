/*
    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2026 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "verification.h"

#include <libkleo/formatting.h>
#include <libkleo/keycache.h>

using namespace Kleo;

static GpgME::UserID findUserIDByMailbox(const GpgME::Key &key, const QString &email)
{
    const auto userIDs{key.userIDs()};
    for (const GpgME::UserID &id : userIDs) {
        if (!Formatting::email(id).compare(email, Qt::CaseInsensitive)) {
            return id;
        }
    }
    return {};
}

QDateTime Kleo::signatureCreationTime(const GpgME::Signature &sig)
{
    return sig.creationTime() != 0 ? QDateTime::fromSecsSinceEpoch(quint32(sig.creationTime())) : QDateTime();
}

Kleo::SignatureData Kleo::assessSignature(const GpgME::Signature &sig, const QString &sender)
{
    SignatureData sigData;
    sigData.sig = sig;

    if (sig.isNull()) {
        return sigData;
    }

    sigData.key = Kleo::KeyCache::instance()->findSigner(sig);

    if (!sender.isEmpty()) {
        sigData.userID = findUserIDByMailbox(sigData.key, sender);
    }
    if (sigData.userID.isNull() && !sigData.key.isNull()) {
        sigData.userID = sigData.key.userID(0);
    }

    sigData.creationTime = signatureCreationTime(sig);

    if ((sig.summary() & GpgME::Signature::Valid)) {
        // Valid (implies Green)
        sigData.status = SignatureStatus::ValidAndFullyTrusted;
    } else if ((sig.summary() & GpgME::Signature::Red)) {
        // Red means either bad signature or validity "never" for the signing key
        sigData.status = (sig.status().code() == GPG_ERR_BAD_SIGNATURE) ? SignatureStatus::Invalid : SignatureStatus::ValidButSignerUntrustworthy;
    } else if ((sig.summary() & GpgME::Signature::KeyMissing)) {
        sigData.status = SignatureStatus::KeyMissing;
    } else if (sig.status().isSuccess()) {
        sigData.status = SignatureStatus::ValidButNotFullyTrusted;
    } else if (sig.status().code() == GPG_ERR_SIG_EXPIRED) {
        sigData.status = SignatureStatus::ValidButSignatureExpired;
    } else if (sig.status().code() == GPG_ERR_KEY_EXPIRED) {
        sigData.status = SignatureStatus::ValidButKeyExpired;
    } else if (sig.status().code() == GPG_ERR_CERT_REVOKED) {
        sigData.status = SignatureStatus::ValidButKeyRevoked;
    } else {
        sigData.status = SignatureStatus::OtherError;
    }

    return sigData;
}
