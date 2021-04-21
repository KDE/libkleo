/*
    utils/test.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "test.h"

#include "cryptoconfig_p.h"

#include <QString>

using namespace Kleo::Tests;

FakeCryptoConfigStringValue::FakeCryptoConfigStringValue(const char *componentName, const char *entryName, const QString &fakeValue)
    : mComponentName(componentName)
    , mEntryName(entryName)
{
    Kleo::Private::setFakeCryptoConfigStringValue(mComponentName, mEntryName, fakeValue);
}

FakeCryptoConfigStringValue::~FakeCryptoConfigStringValue()
{
    Kleo::Private::clearFakeCryptoConfigStringValue(mComponentName, mEntryName);
}
