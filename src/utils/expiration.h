/* -*- mode: c++; c-basic-offset:4 -*-
    utils/expiration.h

    This file is part of Libkleo
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QDate>

class KDateComboBox;

namespace Kleo
{
namespace Expiration
{
struct KLEO_EXPORT DateRange {
    QDate minimum;
    QDate maximum;
};

/**
 * Returns a date a bit before the technically possible latest expiration
 * date (~2106-02-07) that is safe to use as latest expiration date.
 */
KLEO_EXPORT QDate maximumAllowedDate();

/**
 * Returns the earliest allowed expiration date.
 *
 * This is either tomorrow or the configured number of days after today
 * (whichever is later).
 *
 * \sa OpenPGPCertificateCreationConfig::validityPeriodInDaysMin
 */
KLEO_EXPORT QDate minimumExpirationDate();

/**
 * Returns the latest allowed expiration date.
 *
 * If unlimited validity is allowed, then an invalid date is returned.
 * Otherwise, either the configured number of days after today or
 * the maximum allowed date, whichever is earlier, is returned.
 * Additionally, the returned date is never earlier than the minimum
 * expiration date.
 *
 * \sa OpenPGPCertificateCreationConfig::validityPeriodInDaysMax
 */
KLEO_EXPORT QDate maximumExpirationDate();

/**
 * Returns the allowed range for the expiration date.
 *
 * \sa minimumExpirationDate, maximumExpirationDate
 */
KLEO_EXPORT DateRange expirationDateRange();

enum class KLEO_EXPORT ExpirationOnUnlimitedValidity {
    NoExpiration,
    InternalDefaultExpiration,
};

/**
 * Returns a useful value for the default expiration date based on the current
 * date and the configured default validity. If the configured validity is
 * unlimited, then the return value depends on \p onUnlimitedValidity.
 *
 * The returned value is always in the allowed range for the expiration date.
 *
 * \sa expirationDateRange
 */
KLEO_EXPORT QDate defaultExpirationDate(ExpirationOnUnlimitedValidity onUnlimitedValidity);

/**
 * Returns true, if \p date is a valid expiration date.
 */
KLEO_EXPORT bool isValidExpirationDate(const QDate &date);

/**
 * Returns a hint which dates are valid expiration dates for the date
 * combo box \p dateCB.
 * The hint can be used as tool tip or as error message when the user
 * entered an invalid date.
 */
KLEO_EXPORT QString validityPeriodHint();

/**
 * Configures the date combo box \p dateCB for choosing an expiration date.
 *
 * Sets the allowed date range to the \p dateRange, or to the configured
 * validity period range if the minimum date is invalid. If the maximum
 * date is invalid, then the maximumAllowedDate is set as maximum.
 * Also sets a tooltip and a few fixed values to choose from, enables
 * warnings on invalid or not allowed dates, and disables the combo box if
 * the date range spans a single day.
 */
KLEO_EXPORT void setUpExpirationDateComboBox(KDateComboBox *dateCB, const Kleo::Expiration::DateRange &dateRange = {});
}
}
