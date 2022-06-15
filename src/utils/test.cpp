/*
    utils/test.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "test.h"

#include "cryptoconfig_p.h"

#include <QString>

using namespace Kleo::Tests;

FakeCryptoConfigIntValue::FakeCryptoConfigIntValue(const char *componentName, const char *entryName, int fakeValue)
    : mComponentName(componentName)
    , mEntryName(entryName)
{
    Kleo::Private::setFakeCryptoConfigIntValue(mComponentName, mEntryName, fakeValue);
}

FakeCryptoConfigIntValue::~FakeCryptoConfigIntValue()
{
    Kleo::Private::clearFakeCryptoConfigIntValue(mComponentName, mEntryName);
}

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
