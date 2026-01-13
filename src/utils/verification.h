/*
    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2026 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <gpgme++/verificationresult.h>

namespace Kleo
{
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
}
