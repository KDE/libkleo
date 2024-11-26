/*
    utils/stringutils.cpp

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "stringutils.h"

#include <algorithm>

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
