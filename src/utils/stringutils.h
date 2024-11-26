/*
    utils/stringutils.h

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

/**
 * Splits the string @p sv into substrings wherever the character @p c occurs,
 * and returns the list of those strings. If @p maxParts is greater than 0 then
 * the string is split in at most @p maxParts substrings.
 */
KLEO_EXPORT std::vector<std::string_view> split(std::string_view sv, char c, unsigned maxParts = 0);

/**
 * Converts the vector @p stringViews of string views to a vector of strings.
 */
KLEO_EXPORT std::vector<std::string> toStrings(const std::vector<std::string_view> &stringViews);

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
