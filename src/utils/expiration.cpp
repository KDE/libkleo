/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of libkleopatra

    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "expiration.h"
#include "openpgpcertificatecreationconfig.h"

#include <KConfigGroup>
#include <KDateComboBox>
#include <KLocalizedString>
#include <KSharedConfig>
#include <qlatin1stringview.h>

QDate Kleo::Expiration::maximumAllowedDate()
{
    static const QDate maxAllowedDate{2106, 2, 5};
    return maxAllowedDate;
}

QDate Kleo::Expiration::minimumExpirationDate()
{
    return expirationDateRange().minimum;
}

QDate Kleo::Expiration::maximumExpirationDate()
{
    return expirationDateRange().maximum;
}

Kleo::Expiration::DateRange Kleo::Expiration::expirationDateRange()
{
    Kleo::Expiration::DateRange range;

    const auto settings = Kleo::OpenPGPCertificateCreationConfig{};
    const auto today = QDate::currentDate();

    const auto minimumExpiry = std::max(1, settings.validityPeriodInDaysMin());
    range.minimum = std::min(today.addDays(minimumExpiry), maximumAllowedDate());

    const auto maximumExpiry = settings.validityPeriodInDaysMax();
    if (maximumExpiry >= 0) {
        range.maximum = std::min(std::max(today.addDays(maximumExpiry), range.minimum), maximumAllowedDate());
    }

    return range;
}

QDate Kleo::Expiration::defaultExpirationDate(Kleo::Expiration::ExpirationOnUnlimitedValidity onUnlimitedValidity)
{
    QDate expirationDate;

    const auto settings = Kleo::OpenPGPCertificateCreationConfig{};
    const auto defaultExpirationInDays = settings.validityPeriodInDays();
    if (defaultExpirationInDays > 0) {
        expirationDate = QDate::currentDate().addDays(defaultExpirationInDays);
    } else if (defaultExpirationInDays < 0 || onUnlimitedValidity == ExpirationOnUnlimitedValidity::InternalDefaultExpiration) {
        expirationDate = QDate::currentDate().addYears(3);
    }

    const auto allowedRange = expirationDateRange();
    expirationDate = std::max(expirationDate, allowedRange.minimum);
    if (allowedRange.maximum.isValid()) {
        expirationDate = std::min(expirationDate, allowedRange.maximum);
    }

    return expirationDate;
}

bool Kleo::Expiration::isValidExpirationDate(const QDate &date)
{
    const auto allowedRange = expirationDateRange();
    if (date.isValid()) {
        return (date >= allowedRange.minimum //
                && ((allowedRange.maximum.isValid() && date <= allowedRange.maximum) //
                    || (!allowedRange.maximum.isValid() && date <= maximumAllowedDate())));
    } else {
        return !allowedRange.maximum.isValid();
    }
}

static QString dateToString(const QDate &date, QWidget *widget)
{
    // workaround for QLocale using "yy" way too often for years
    // stolen from KDateComboBox
    auto locale = widget ? widget->locale() : QLocale{};
    const auto dateFormat = (locale
                                 .dateFormat(QLocale::ShortFormat) //
                                 .replace(QLatin1StringView{"yy"}, QLatin1StringView{"yyyy"})
                                 .replace(QLatin1StringView{"yyyyyyyy"}, QLatin1StringView{"yyyy"}));
    return locale.toString(date, dateFormat);
}

static QString validityPeriodHint(const Kleo::Expiration::DateRange &dateRange, QWidget *widget)
{
    // the minimum date is always valid
    if (dateRange.maximum.isValid()) {
        if (dateRange.maximum == dateRange.minimum) {
            return i18nc("@info", "The date cannot be changed.");
        } else {
            return i18nc("@info ... between <a date> and <another date>.",
                         "Enter a date between %1 and %2.",
                         dateToString(dateRange.minimum, widget),
                         dateToString(dateRange.maximum, widget));
        }
    } else {
        return i18nc("@info ... between <a date> and <another date>.",
                     "Enter a date between %1 and %2.",
                     dateToString(dateRange.minimum, widget),
                     dateToString(Kleo::Expiration::maximumAllowedDate(), widget));
    }
}

QString Kleo::Expiration::validityPeriodHint()
{
    return ::validityPeriodHint(expirationDateRange(), nullptr);
}

void Kleo::Expiration::setUpExpirationDateComboBox(KDateComboBox *dateCB, const Kleo::Expiration::DateRange &range)
{
    const auto dateRange = range.minimum.isValid() ? range : expirationDateRange();
    // enable warning on invalid or not allowed dates
    dateCB->setOptions(KDateComboBox::EditDate | KDateComboBox::SelectDate | KDateComboBox::DatePicker | KDateComboBox::DateKeywords
                       | KDateComboBox::WarnOnInvalid);
    const auto hintAndErrorMessage = validityPeriodHint(dateRange, dateCB);
    dateCB->setDateRange(dateRange.minimum, dateRange.maximum.isValid() ? dateRange.maximum : maximumAllowedDate(), hintAndErrorMessage, hintAndErrorMessage);
    if (dateRange.minimum == dateRange.maximum) {
        // only one date is allowed, so that changing it no sense
        dateCB->setEnabled(false);
    }
    dateCB->setToolTip(hintAndErrorMessage);
    const QDate today = QDate::currentDate();
    dateCB->setDateMap({
        {today.addYears(3), i18nc("@item:inlistbox", "Three years from now")},
        {today.addYears(2), i18nc("@item:inlistbox", "Two years from now")},
        {today.addYears(1), i18nc("@item:inlistbox", "One year from now")},
    });
}
