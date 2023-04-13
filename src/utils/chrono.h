/*
    utils/chrono.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QMetaType>

#include <chrono>

namespace Kleo::chrono
{
// typedef for duration in days (defined in C++20)
using days = std::chrono::duration<std::chrono::seconds::rep, std::ratio<86400>>;
}

Q_DECLARE_METATYPE(Kleo::chrono::days)
