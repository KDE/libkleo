/*
    oidmap.h

    This file is part of libkleo, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 Ingo Klöcker <kloecker@kde.org>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

class QString;


KLEO_EXPORT const char *oidForAttributeName(const QString &attr);

KLEO_EXPORT const char *attributeNameForOID(const char *oid);
