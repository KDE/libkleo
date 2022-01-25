/* -*- mode: c++; c-basic-offset:4 -*-
    utils/hex.h

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <string>

#include "kleo_export.h"

class QByteArray;

namespace Kleo
{

KLEO_EXPORT std::string hexencode(const char *s);
KLEO_EXPORT std::string hexdecode(const char *s);

KLEO_EXPORT std::string hexencode(const std::string &s);
KLEO_EXPORT std::string hexdecode(const std::string &s);

KLEO_EXPORT QByteArray hexencode(const QByteArray &s);
KLEO_EXPORT QByteArray hexdecode(const QByteArray &s);

}

