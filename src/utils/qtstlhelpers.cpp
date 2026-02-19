/*
    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "qtstlhelpers.h"

std::vector<std::string> Kleo::toStdStrings(const QList<QString> &list)
{
    std::vector<std::string> result;

    result.reserve(list.size());
    std::transform(std::begin(list), std::end(list), std::back_inserter(result), std::mem_fn(&QString::toStdString));

    return result;
}
