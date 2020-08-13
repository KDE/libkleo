/* -*- mode: c++; c-basic-offset:4 -*-
    utils/hex.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifndef __KLEOPATRA_UTILS_HEX_H__
#define __KLEOPATRA_UTILS_HEX_H__

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

#endif /* __KLEOPATRA_UTILS_HEX_H__ */
