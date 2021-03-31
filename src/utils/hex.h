/* -*- mode: c++; c-basic-offset:4 -*-
    utils/hex.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <string>

class QByteArray;

namespace Kleo
{

std::string hexencode(const char *s);
std::string hexdecode(const char *s);

std::string hexencode(const std::string &s);
std::string hexdecode(const std::string &s);

QByteArray hexencode(const QByteArray &s);
QByteArray hexdecode(const QByteArray &s);

}

