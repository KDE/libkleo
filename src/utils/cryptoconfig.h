/*
    utils/cryptoconfig.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

class QString;

namespace Kleo
{

KLEO_EXPORT QString getCryptoConfigStringValue(const char *componentName, const char *entryName);

}
