/* -*- mode: c++; c-basic-offset:4 -*-
    utils/compliance.cpp

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "compliance.h"

#include "cryptoconfig.h"
#include "gnupg.h"

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
