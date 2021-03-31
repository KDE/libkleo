/*
    kleo/debug.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

namespace Kleo
{
class KeyGroup;
}

class QDebug;

KLEO_EXPORT QDebug operator<<(QDebug debug, const Kleo::KeyGroup &group);

