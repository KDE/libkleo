/*
    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "stringutils.h"

#include <libkleo_debug.h>

#include <algorithm>
#include <charconv>
#include <system_error>

std::vector<std::string_view> Kleo::split(std::string_view sv, char c, unsigned maxParts)
{
    if (maxParts == 1) {
        return {sv};
    }

    std::vector<std::string_view> result;
    result.reserve(std::min(maxParts, static_cast<unsigned>(std::count(sv.begin(), sv.end(), c))));

    auto start = 0;
    auto end = sv.find(c, start);
    while ((end != sv.npos) && (maxParts == 0 || result.size() < maxParts - 1)) {
        result.push_back(sv.substr(start, end - start));
        start = end + 1;
        end = sv.find(c, start);
    }
    result.push_back(sv.substr(start));

    return result;
}

std::vector<std::string> Kleo::toStrings(const std::vector<std::string_view> &stringViews)
{
    std::vector<std::string> result;
    result.reserve(stringViews.size());
    for (const auto &sv : stringViews) {
        result.emplace_back(sv);
    }
    return result;
}

std::optional<int> Kleo::svToInt(std::string_view sv)
{
    std::optional<int> result;
    int tmp;
    const auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), tmp);
    if (ec != std::errc()) {
        qCDebug(LIBKLEO_LOG) << __func__ << "Error: Failed to convert" << sv << "to int (" << std::make_error_code(ec).message() << ")";
    } else if (ptr != sv.data() + sv.size()) {
        qCDebug(LIBKLEO_LOG) << __func__ << "Error: Failed to convert" << sv << "to int ( invalid character at position" << (ptr - sv.data()) << ")";
    } else {
        result = tmp;
    }
    return result;
}
