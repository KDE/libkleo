/*
    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QString>
#include <QStringList>

namespace Kleo
{
namespace DNAttributes
{
KLEO_EXPORT QStringList order();
KLEO_EXPORT void setOrder(const QStringList &order);

KLEO_EXPORT QStringList defaultOrder();

KLEO_EXPORT QStringList names();
KLEO_EXPORT QString nameToLabel(const QString &name);
}
}
