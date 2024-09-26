/*
    models/keylist.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

namespace Kleo
{
static const int ClipboardRole = 0x01FF;

namespace KeyList
{
// clang-format off
static const int FingerprintRole = 0xF1;
static const int KeyRole         = 0xF2;
static const int GroupRole       = 0xF3;
static const int UserIDRole      = 0xF4;
// clang-format on

enum Columns {
    PrettyName,
    PrettyEMail,
    ValidFrom,
    ValidUntil,
    TechnicalDetails,
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
    Algorithm,
    Keygrip,
    NumColumns,
    Icon = PrettyName, // which column shall the icon be displayed in?
};

enum Options {
    AllKeys,
    SecretKeysOnly,
    IncludeGroups,
};
}
}
