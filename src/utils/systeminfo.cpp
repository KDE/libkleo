/* -*- mode: c++; c-basic-offset:4 -*-
    utils/systeminfo.cpp

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "systeminfo.h"

#include <QByteArray>
#include <QtSystemDetection>

// #include "libkleo_debug.h"
#ifdef Q_OS_WIN
#include "windows.h"
// #include "gnupg-registry.h"
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

bool win_isDarkModeActive()
{
    /* This is a bit complicated. Qt does not detect this correctly
     * for high contrast mode with white contrast. */

    // First check for white background. That is set in High contrast
    // white theme.
    DWORD color = GetSysColor(COLOR_WINDOW);
    if (color == 0xFFFFFF) {
        return false;
    }
    // Windows 10 has only one white High Contrast mode. The other
    // three are dark.
    if (win_isHighContrastModeActive()) {
        return true;
    }

#if 0
    // This is not enabled because although Qt does check for this, the theme
    // does not switch accordingly in tests. So we would have white icons on a
    // bright window.
    //
    // The user may have customized a dark theme. Then AppsUseLightTheme is 0
    char *val = read_w32_registry_string ("HKEY_CURRENT_USER",
                   "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                   "AppsUseLightTheme");
    bool ret = false;
    if (val) {
        ret = !((DWORD) *val);
        free (val);
        return ret;
    }
#endif
    // Nothing set -> default to bright.
    return false;
}
}
#endif

bool Kleo::SystemInfo::isHighContrastModeActive()
{
    static bool forceHighContrastMode = qgetenv("KLEO_HIGH_CONTRAST_MODE").toInt();
#ifdef Q_OS_WIN
    static bool highContrastModeActive = forceHighContrastMode || win_isHighContrastModeActive();
    return highContrastModeActive;
#else
    return forceHighContrastMode;
#endif
}

bool Kleo::SystemInfo::isDarkModeActive()
{
#ifdef Q_OS_WIN
    return win_isDarkModeActive();
#else
    // Don't know
    return isHighContrastModeActive();
#endif
}
