/* -*- mode: c++; c-basic-offset:4 -*-
    utils/hex.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "hex.h"

#include "kleo/kleoexception.h"

#include <KLocalizedString>

#include <QString>
#include <QByteArray>

using namespace Kleo;

static unsigned char unhex(unsigned char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    const char cch = ch;
    throw Kleo::Exception(gpg_error(GPG_ERR_ASS_SYNTAX),
                    i18n("Invalid hex char '%1' in input stream.",
                         QString::fromLatin1(&cch, 1)));
}

std::string Kleo::hexdecode(const std::string &in)
{
    std::string result;
    result.reserve(in.size());
    for (std::string::const_iterator it = in.begin(), end = in.end(); it != end; ++it)
        if (*it == '%') {
            ++it;
            unsigned char ch = '\0';
            if (it == end)
                throw Exception(gpg_error(GPG_ERR_ASS_SYNTAX),
                                i18n("Premature end of hex-encoded char in input stream"));
            ch |= unhex(*it) << 4;
            ++it;
            if (it == end)
                throw Exception(gpg_error(GPG_ERR_ASS_SYNTAX),
                                i18n("Premature end of hex-encoded char in input stream"));
            ch |= unhex(*it);
            result.push_back(ch);
        } else if (*it == '+') {
            result += ' ';
        } else  {
            result.push_back(*it);
        }
    return result;
}

std::string Kleo::hexencode(const std::string &in)
{
    std::string result;
    result.reserve(3 * in.size());

    static const char hex[] = "0123456789ABCDEF";

    for (std::string::const_iterator it = in.begin(), end = in.end(); it != end; ++it)
        switch (const unsigned char ch = *it) {
        default:
            if ((ch >= '!' && ch <= '~') || ch > 0xA0) {
                result += ch;
                break;
            }
        // else fall through
        case ' ':
            result += '+';
            break;
        case '"':
        case '#':
        case '$':
        case '%':
        case '\'':
        case '+':
        case '=':
            result += '%';
            result += hex[(ch & 0xF0) >> 4 ];
            result += hex[(ch & 0x0F)      ];
            break;
        }

    return result;
}

std::string Kleo::hexdecode(const char *in)
{
    if (!in) {
        return std::string();
    }
    return hexdecode(std::string(in));
}

std::string Kleo::hexencode(const char *in)
{
    if (!in) {
        return std::string();
    }
    return hexencode(std::string(in));
}

QByteArray Kleo::hexdecode(const QByteArray &in)
{
    if (in.isNull()) {
        return QByteArray();
    }
    const std::string result = hexdecode(std::string(in.constData()));
    return QByteArray(result.data(), result.size());
}

QByteArray Kleo::hexencode(const QByteArray &in)
{
    if (in.isNull()) {
        return QByteArray();
    }
    const std::string result = hexencode(std::string(in.constData()));
    return QByteArray(result.data(), result.size());
}
