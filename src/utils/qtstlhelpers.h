/*
    utils/qtstlhelpers.h

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QList>

#include <string>
#include <vector>

class QString;

namespace Kleo
{

KLEO_EXPORT std::vector<std::string> toStdStrings(const QList<QString> &list);

}
