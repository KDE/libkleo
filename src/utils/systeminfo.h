/* -*- mode: c++; c-basic-offset:4 -*-
    utils/systeminfo.h

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

namespace Kleo::SystemInfo
{

KLEO_EXPORT bool isHighContrastModeActive();

KLEO_EXPORT bool isHighContrastColorSchemeInUse();
}
