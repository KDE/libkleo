/*
    oidmap.cpp

    This file is part of libkleo, the KDE keymanagement library
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 Ingo Klöcker <kloecker@kde.org>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "oidmap.h"

#include <QString>

static const struct {
    const char *name;
    const char *oid;
} oidmap[] = {
    // clang-format off
    // keep them ordered by oid:
    {"SP",                "ST"                  }, // hack to show the Sphinx-required/desired SP for
    // StateOrProvince, otherwise known as ST or even S
    {"NameDistinguisher", "0.2.262.1.10.7.20"   },
    {"EMAIL",             "1.2.840.113549.1.9.1"},
    {"SN",                "2.5.4.4"             },
    {"SerialNumber",      "2.5.4.5"             },
    {"T",                 "2.5.4.12"            },
    {"D",                 "2.5.4.13"            },
    {"BC",                "2.5.4.15"            },
    {"ADDR",              "2.5.4.16"            },
    {"PC",                "2.5.4.17"            },
    {"GN",                "2.5.4.42"            },
    {"Pseudo",            "2.5.4.65"            },
    // clang-format on
};
static const unsigned int numOidMaps = sizeof oidmap / sizeof *oidmap;

const char *Kleo::oidForAttributeName(const QString &attr)
{
    QByteArray attrUtf8 = attr.toUtf8();
    for (unsigned int i = 0; i < numOidMaps; ++i) {
        if (qstricmp(attrUtf8.constData(), oidmap[i].name) == 0) {
            return oidmap[i].oid;
        }
    }
    return nullptr;
}

const char *Kleo::attributeNameForOID(const char *oid)
{
    for (unsigned int i = 0; i < numOidMaps; ++i) {
        if (qstricmp(oid, oidmap[i].oid) == 0) {
            return oidmap[i].name;
        }
    }
    return nullptr;
}
