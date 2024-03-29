/*
    utils/cryptoconfig.h

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

KLEO_EXPORT int getCryptoConfigIntValue(const char *componentName, const char *entryName, int defaultValue);

KLEO_EXPORT QString getCryptoConfigStringValue(const char *componentName, const char *entryName);

KLEO_EXPORT QList<QUrl> getCryptoConfigUrlList(const char *componentName, const char *entryName);

}
