/*
    oidmap.cpp

    This file is part of libkleo, the KDE keymanagement library
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "oidmap.h"

#include <QString>

const char *oidForAttributeName(const QString &attr)
{
    QByteArray attrUtf8 = attr.toUtf8();
    for (unsigned int i = 0; i < numOidMaps; ++i) {
        if (qstricmp(attrUtf8.constData(), oidmap[i].name) == 0) {
            return oidmap[i].oid;
        }
    }
    return nullptr;
}
