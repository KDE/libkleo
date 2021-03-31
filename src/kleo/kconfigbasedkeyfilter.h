/*
    kconfigbasedkeyfilter.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "defaultkeyfilter.h"

class KConfigGroup;

namespace Kleo
{

class KLEO_EXPORT KConfigBasedKeyFilter : public DefaultKeyFilter
{
public:
    explicit KConfigBasedKeyFilter(const KConfigGroup &group);
};

}

