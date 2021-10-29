/*
    utils/string.cpp

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "stringutils.h"

std::vector<std::string> Kleo::split(const std::string &s, char c)
{
    std::vector<std::string> result;

    auto start = 0;
    auto end = s.find(c, start);
    while (end != s.npos) {
        result.push_back(s.substr(start, end - start));
        start = end + 1;
        end = s.find(c, start);
    }
    result.push_back(s.substr(start));

    return result;
}
