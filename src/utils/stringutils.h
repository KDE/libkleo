/*
    utils/string.h

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <string>
#include <vector>

#include "kleo_export.h"

namespace Kleo
{

/** Splits the string @p s into substrings wherever the character @p c occurs,
 *  and returns the list of those strings. */
KLEO_EXPORT std::vector<std::string> split(const std::string &s, char c);

}
