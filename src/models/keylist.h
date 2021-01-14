/*
    models/keylist.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifndef LIBKLEO_KEYLIST_H
#define LIBKLEO_KEYLIST_H

namespace Kleo
{
namespace KeyList
{
    static const int FingerprintRole = 0xF1;
    static const int KeyRole = 0xF2;

    enum Columns {
        PrettyName,
        PrettyEMail,
        ValidFrom,
        ValidUntil,
        TechnicalDetails,
        ShortKeyID,
        KeyID,
        Fingerprint,
        Issuer,
        SerialNumber,
        OwnerTrust,
        Origin,
        LastUpdate,
        Validity,
        Summary, // Short summary line
        Remarks, // Additional remark notations
        NumColumns,
        Icon = PrettyName // which column shall the icon be displayed in?
    };
}
}

#endif /* LIBKLEO_KEYLIST_H */
