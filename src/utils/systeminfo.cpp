/* -*- mode: c++; c-basic-offset:4 -*-
    utils/systeminfo.cpp

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "systeminfo.h"

#include <KColorSchemeManager>

#include <QByteArray>

// #include "libkleo_debug.h"
#ifdef Q_OS_WIN
#include "windows.h"
#endif

#ifdef Q_OS_WIN
namespace
{
bool win_isHighContrastModeActive()
{
    HIGHCONTRAST result;
    result.cbSize = sizeof(HIGHCONTRAST);
    if (SystemParametersInfo(SPI_GETHIGHCONTRAST, result.cbSize, &result, 0)) {
        return (result.dwFlags & HCF_HIGHCONTRASTON);
    }
    return false;
}
}
#endif

bool Kleo::SystemInfo::isHighContrastModeActive()
{
    static bool forceHighContrastMode = qgetenv("KLEO_HIGH_CONTRAST_MODE").toInt();
#ifdef Q_OS_WIN
    return forceHighContrastMode || win_isHighContrastModeActive();
#else
    return forceHighContrastMode;
#endif
}

bool Kleo::SystemInfo::isHighContrastColorSchemeInUse()
{
    return KColorSchemeManager::instance()->activeSchemeId().isEmpty() // the default scheme is in use
        && isHighContrastModeActive();
}
