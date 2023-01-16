/* -*- mode: c++; c-basic-offset:4 -*-
    utils/compliance.cpp

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "compliance.h"

#include "algorithm.h"
#include "cryptoconfig.h"
#include "gnupg.h"
#include "stringutils.h"
#include "systeminfo.h"

#include <libkleo/keyfiltermanager.h>

#include <KColorScheme>
#include <KLocalizedString>

#include <QPushButton>

bool Kleo::DeVSCompliance::isActive()
{
    return getCryptoConfigStringValue("gpg", "compliance") == QLatin1String{"de-vs"};
}

bool Kleo::DeVSCompliance::isCompliant()
{
    if (!isActive()) {
        return false;
    }
    // The pseudo option compliance_de_vs was fully added in 2.2.34;
    // For versions between 2.2.28 and 2.2.33 there was a broken config
    // value with a wrong type. So for them we add an extra check. This
    // can be removed in future versions because for GnuPG we could assume
    // non-compliance for older versions as versions of Kleopatra for
    // which this matters are bundled with new enough versions of GnuPG anyway.
    if (engineIsVersion(2, 2, 28) && !engineIsVersion(2, 2, 34)) {
        return true;
    }
    return getCryptoConfigIntValue("gpg", "compliance_de_vs", 0) != 0;
}

bool Kleo::DeVSCompliance::algorithmIsCompliant(std::string_view algo)
{
    static const std::vector<std::string> compliantAlgorithms = {
        "brainpoolP256r1",
        "brainpoolP384r1",
        "brainpoolP512r1",
        "rsa3072",
        "rsa4096",
    };

    return !isActive() || Kleo::contains(compliantAlgorithms, algo);
}

void Kleo::DeVSCompliance::decorate(QPushButton *button)
{
    decorate(button, isCompliant());
}

void Kleo::DeVSCompliance::decorate(QPushButton *button, bool compliant)
{
    if (!button) {
        return;
    }
    if (compliant) {
        button->setIcon(QIcon::fromTheme(QStringLiteral("security-high")));
        if (!SystemInfo::isHighContrastModeActive()) {
            const auto bgColor = KColorScheme(QPalette::Active, KColorScheme::View).background(KColorScheme::PositiveBackground).color().name();
            button->setStyleSheet(QStringLiteral("QPushButton { background-color: %1; };").arg(bgColor));
        }
    } else {
        button->setIcon(QIcon::fromTheme(QStringLiteral("security-medium")));
        if (!SystemInfo::isHighContrastModeActive()) {
            const auto bgColor = KColorScheme(QPalette::Active, KColorScheme::View).background(KColorScheme::NegativeBackground).color().name();
            button->setStyleSheet(QStringLiteral("QPushButton { background-color: %1; };").arg(bgColor));
        }
    }
}

QString Kleo::DeVSCompliance::name()
{
    return name(isCompliant());
}

QString Kleo::DeVSCompliance::name(bool compliant)
{
    const auto filterId = compliant ? QStringLiteral("de-vs-filter") : QStringLiteral("not-de-vs-filter");
    if (auto filter = KeyFilterManager::instance()->keyFilterByID(filterId)) {
        return filter->name();
    }
    return compliant ? i18n("VS-NfD compliant") : i18n("Not VS-NfD compliant");
}
