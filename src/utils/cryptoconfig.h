/*
    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QList>

class QString;
class QUrl;

namespace Kleo
{

/**
 * Returns \c true if option \a entryName of component \a componentName is set,
 * otherwise \c false.
 *
 * Can only be used for config entries with scalar value of type CryptoConfigEntry::ArgType_None.
 */
KLEO_EXPORT bool getCryptoConfigBoolValue(const char *componentName, const char *entryName);

KLEO_EXPORT int getCryptoConfigIntValue(const char *componentName, const char *entryName, int defaultValue);

KLEO_EXPORT QString getCryptoConfigStringValue(const char *componentName, const char *entryName);

KLEO_EXPORT QList<QUrl> getCryptoConfigUrlList(const char *componentName, const char *entryName);

}
