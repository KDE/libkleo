/*
    utils/compat.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

namespace QGpgME
{
class CryptoConfig;
class CryptoConfigEntry;
}

namespace Kleo
{

KLEO_EXPORT QGpgME::CryptoConfigEntry *getCryptoConfigEntry(const QGpgME::CryptoConfig *config, const char *componentName, const char *entryName);

}

