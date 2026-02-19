/*
    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <vector>

class QString;

namespace Kleo
{
class KeyGroup;

KLEO_EXPORT std::vector<KeyGroup> readKeyGroups(const QString &filename);

enum class WriteKeyGroups {
    Success,
    InvalidFilename,
    Error,
};

KLEO_EXPORT WriteKeyGroups writeKeyGroups(const QString &filename, const std::vector<KeyGroup> &groups);

}
