/*
    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2026 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QDateTime>

#include <gpgme++/key.h>
#include <gpgme++/verificationresult.h>

namespace Kleo
{
enum class SignatureStatus {
    NoSignature,
    KeyMissing, // Signing key is missing
    ValidAndFullyTrusted, // Good signature made with fully trusted key
    ValidButNotFullyTrusted, // Good signature made with not fully trusted key
    ValidButSignatureExpired, // Good signature but expired signature (only occurs for OpenPGP)
    ValidButKeyExpired, // Good signature but expired signing key
    ValidButKeyRevoked, // Good signature but revoked signing key
    ValidButSignerUntrustworthy, // Good signature with key flagged as untrustworthy (== must not be trusted)
    Invalid, // Signature does not match the data
    OtherError, // Another error occurred while checking the signature
};

struct SignatureData {
    SignatureStatus status = SignatureStatus::NoSignature;
    GpgME::Signature sig;
    GpgME::Key key;
    GpgME::UserID userID;
    QDateTime creationTime;
};

/*!
 * Returns true if the signature \a sig is a good signature, i.e. it matches the signed data.
 * It does not take into account the validity of the signing key, i.e. use it with care.
 * Check the summary of \a sig if you want to know whether gpgme considers the signature Green, Red,
 * or something else.
 *
 * \note a signature can be good, bad, or ugly (i.e. missing signing key or some other error)
 */
inline bool signatureIsGood(const GpgME::Signature &sig)
{
    return (sig.status().code() == GPG_ERR_NO_ERROR) //
        || (sig.status().code() == GPG_ERR_SIG_EXPIRED) //
        || (sig.status().code() == GPG_ERR_KEY_EXPIRED) //
        || (sig.status().code() == GPG_ERR_CERT_REVOKED);
}

/*!
 * Returns true if the signature \a sig is a bad signature, i.e. it doesn't match the signed data.
 * It does not take into account the validity of the signing key, i.e. use it with care.
 * Check the summary of \a sig if you want to know whether gpgme considers the signature Green, Red,
 * or something else.
 *
 * \note a signature can be good, bad, or ugly (i.e. missing signing key or some other error)
 */
inline bool signatureIsBad(const GpgME::Signature &sig)
{
    return (sig.status().code() == GPG_ERR_BAD_SIGNATURE);
}

/*!
 * Returns the creation time of the signature \a sig or an invalid QDateTime if no creation time is
 * available (i.e. if sig.creationTime() is 0).
 */
KLEO_EXPORT QDateTime signatureCreationTime(const GpgME::Signature &sig);

/*!
 * Assesses a signature \a sig.
 *
 * Looks at the properties of the signature \a sig and makes an assessment about the status of the signature.
 * Additionally, it returns the key that was used for creating the signature and the creation time of the
 * signature (if available). If \a sender is given then it looks for a matching user ID. Otherwise, the primary
 * user ID of the key is returned.
 *
 * @param signature The signature to assess.
 * @param sender The sender of the signature (e.g. in case of email).
 */
KLEO_EXPORT SignatureData assessSignature(const GpgME::Signature &sig, const QString &sender = {});
}
