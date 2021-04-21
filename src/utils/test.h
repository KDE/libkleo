/*
    utils/test.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <string>

class QString;

namespace Kleo
{

namespace Tests
{

class KLEO_EXPORT FakeCryptoConfigStringValue
{
public:
    FakeCryptoConfigStringValue(const char *componentName, const char *entryName, const QString &fakeValue);
    ~FakeCryptoConfigStringValue();

private:
    std::string mComponentName;
    std::string mEntryName;
};

}

}
