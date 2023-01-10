/*
    utils/string.h

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <string>
#include <string_view>
#include <vector>

namespace Kleo
{

/** Splits the string @p s into substrings wherever the character @p c occurs,
 *  and returns the list of those strings. */
KLEO_EXPORT std::vector<std::string> split(const std::string &s, char c);

/**
 * Returns true if the string @p sv begins with the string @p prefix, false
 * otherwise.
 */
inline bool startsWith(std::string_view sv, std::string_view prefix)
{
#ifdef __cpp_lib_starts_ends_with
    return sv.starts_with(prefix);
#else
    return sv.substr(0, prefix.size()) == prefix;
#endif
}
}
