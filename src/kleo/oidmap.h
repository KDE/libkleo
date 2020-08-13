/*
    oidmap.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifndef __KLEO_OIDMAP_H__
#define __KLEO_OIDMAP_H__

static const struct {
    const char *name;
    const char *oid;
} oidmap[] = {
    // keep them ordered by oid:
    { "SP", "ST" }, // hack to show the Sphinx-required/desired SP for
    // StateOrProvince, otherwise known as ST or even S
    { "NameDistinguisher", "0.2.262.1.10.7.20" },
    { "EMAIL", "1.2.840.113549.1.9.1" },
    { "SN", "2.5.4.4" },
    { "SerialNumber", "2.5.4.5" },
    { "T", "2.5.4.12" },
    { "D", "2.5.4.13" },
    { "BC", "2.5.4.15" },
    { "ADDR", "2.5.4.16" },
    { "PC", "2.5.4.17" },
    { "GN", "2.5.4.42" },
    { "Pseudo", "2.5.4.65" },
};
static const unsigned int numOidMaps = sizeof oidmap / sizeof * oidmap;

#endif // __KLEO_OIDMAP_H__
