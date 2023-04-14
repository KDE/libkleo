/*
    kleo/expirycheckerconfig.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#ifdef KPim6Libkleo_EXPORTS
#include <expirycheckerconfigbase.h>
#else
#include <libkleo/expirycheckerconfigbase.h>
#endif

namespace Kleo
{

class ExpiryCheckerSettings;

class KLEO_EXPORT ExpiryCheckerConfig : public Kleo::ExpiryCheckerConfigBase
{
public:
    using ExpiryCheckerConfigBase::ExpiryCheckerConfigBase;

    ExpiryCheckerSettings settings() const;
};

}
