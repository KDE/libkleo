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
#include "keyhelpers.h"
#include "stringutils.h"
#include "systeminfo.h"

#include <libkleo/debug.h>
#include <libkleo/keyfiltermanager.h>

#include <libkleo_debug.h>

#include <KColorScheme>
#include <KLocalizedString>

#include <QPushButton>

#include <gpgme++/key.h>

using namespace Kleo;

bool Kleo::DeVSCompliance::isActive()
{
    return getCryptoConfigStringValue("gpg", "compliance") == QLatin1StringView{"de-vs"};
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

bool Kleo::DeVSCompliance::isBetaCompliance()
{
    if (!isActive()) {
        return false;
    }
    // compliance_de_vs > 2000: GnuPG has not yet been approved for VS-NfD or is beta, but we shall assume approval
    return getCryptoConfigIntValue("gpg", "compliance_de_vs", 0) > 2000;
}

bool Kleo::DeVSCompliance::algorithmIsCompliant(std::string_view algo)
{
    return !isActive() || Kleo::contains(compliantAlgorithms(), algo);
}

bool Kleo::DeVSCompliance::allSubkeysAreCompliant(const GpgME::Key &key)
{
    if (!isActive()) {
        return true;
    }
    // there is at least one usable subkey
    const auto usableSubkeys = Kleo::count_if(key.subkeys(), [](const auto &sub) {
        return !sub.isExpired() && !sub.isRevoked();
    });
    if (usableSubkeys == 0) {
        qCDebug(LIBKLEO_LOG) << __func__ << "No usable subkeys found for key" << key;
        return false;
    }
    // and all usable subkeys are compliant
    return Kleo::all_of(key.subkeys(), [](const auto &sub) {
        return sub.isDeVs() || sub.isExpired() || sub.isRevoked() || (!sub.canSign() && !sub.canEncrypt() && !sub.canCertify() && sub.canAuthenticate());
    });
}

bool Kleo::DeVSCompliance::userIDIsCompliant(const GpgME::UserID &id)
{
    if (!isActive()) {
        return true;
    }
    return (id.parent().keyListMode() & GpgME::Validate) //
        && !id.isRevoked() //
        && id.validity() >= GpgME::UserID::Full //
        && allSubkeysAreCompliant(id.parent());
}

bool Kleo::DeVSCompliance::keyIsCompliant(const GpgME::Key &key)
{
    if (!isActive()) {
        return true;
    }
    return (key.keyListMode() & GpgME::Validate) //
        && allUserIDsHaveFullValidity(key) //
        && allSubkeysAreCompliant(key);
}

const std::vector<std::string> &Kleo::DeVSCompliance::compliantAlgorithms()
{
    static std::vector<std::string> compliantAlgos;
    if (!isActive()) {
        return Kleo::availableAlgorithms();
    }
    if (compliantAlgos.empty()) {
        compliantAlgos.reserve(7);
        compliantAlgos = {
            "brainpoolP256r1",
            "brainpoolP384r1",
            "brainpoolP512r1",
            "rsa3072",
            "rsa4096",
        };
#if GPGMEPP_SUPPORTS_KYBER
        if (engineIsVersion(2, 5, 2)) {
            compliantAlgos.insert(compliantAlgos.end(),
                                  {
                                      "ky768_bp256",
                                      "ky1024_bp384",
                                  });
        }
#endif
    };
    return compliantAlgos;
}

const std::vector<std::string> &Kleo::DeVSCompliance::preferredCompliantAlgorithms()
{
    static std::vector<std::string> result;
    if (result.empty()) {
        const auto &preferredAlgos = Kleo::preferredAlgorithms();
        result.reserve(preferredAlgos.size());
        Kleo::copy_if(preferredAlgos, std::back_inserter(result), Kleo::DeVSCompliance::algorithmIsCompliant);
    }
    return result;
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
        auto buttonPalette = button->palette();
        KColorScheme::adjustBackground(buttonPalette, KColorScheme::PositiveBackground, button->backgroundRole(), KColorScheme::Button);
        button->setPalette(buttonPalette);
    } else {
        button->setIcon(QIcon::fromTheme(QStringLiteral("security-medium")));
        auto buttonPalette = button->palette();
        KColorScheme::adjustBackground(buttonPalette, KColorScheme::NegativeBackground, button->backgroundRole(), KColorScheme::Button);
        button->setPalette(buttonPalette);
    }
}

QString Kleo::DeVSCompliance::name()
{
    return name(isCompliant());
}

static QString complianceName(bool compliant)
{
    const auto filterId = compliant ? QStringLiteral("de-vs-filter") : QStringLiteral("not-de-vs-filter");
    if (auto filter = KeyFilterManager::instance()->keyFilterByID(filterId)) {
        return filter->name();
    }
    return compliant ? i18n("VS-NfD compliant") : i18n("Not VS-NfD compliant");
}

QString Kleo::DeVSCompliance::name(bool compliant)
{
    if (!isActive()) {
        return {};
    }
    if (compliant && isBetaCompliance()) {
        return i18nc("@info append beta-marker to compliance", "%1 (beta)", complianceName(compliant));
    }
    return complianceName(compliant);
}
