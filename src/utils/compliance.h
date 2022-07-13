/* -*- mode: c++; c-basic-offset:4 -*-
    utils/compliance.h

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

namespace Kleo::DeVSCompliance
{

/**
 * Returns true, if compliance mode "de-vs" is configured for GnuPG.
 * Note: It does not check whether the used GnuPG is actually compliant.
 */
KLEO_EXPORT bool isActive();

/**
 * Returns true, if compliance mode "de-vs" is configured for GnuPG and if
 * GnuPG passes a basic compliance check, i.e. at least libgcrypt and the used
 * RNG are compliant.
 */
KLEO_EXPORT bool isCompliant();

}
