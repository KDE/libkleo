/*
    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "expirycheckersettings.h"

using namespace Kleo;

class ExpiryCheckerSettings::Private
{
public:
    Kleo::chrono::days ownKeyThreshold;
    Kleo::chrono::days otherKeyThreshold;
    Kleo::chrono::days rootCertThreshold;
    Kleo::chrono::days chainCertThreshold;
};

ExpiryCheckerSettings::ExpiryCheckerSettings(Kleo::chrono::days ownKeyThreshold,
                                             Kleo::chrono::days otherKeyThreshold,
                                             Kleo::chrono::days rootCertThreshold,
                                             Kleo::chrono::days chainCertThreshold)
    : d{new Private{ownKeyThreshold, otherKeyThreshold, rootCertThreshold, chainCertThreshold}}
{
}

ExpiryCheckerSettings::~ExpiryCheckerSettings() = default;

ExpiryCheckerSettings::ExpiryCheckerSettings(const ExpiryCheckerSettings &other)
    : d{new Private{*other.d}}
{
}

ExpiryCheckerSettings &ExpiryCheckerSettings::operator=(const ExpiryCheckerSettings &other)
{
    *d = *other.d;
    return *this;
}

ExpiryCheckerSettings::ExpiryCheckerSettings(ExpiryCheckerSettings &&other) = default;

ExpiryCheckerSettings &ExpiryCheckerSettings::operator=(ExpiryCheckerSettings &&other) = default;

void ExpiryCheckerSettings::setOwnKeyThreshold(Kleo::chrono::days threshold)
{
    d->ownKeyThreshold = threshold;
}

Kleo::chrono::days ExpiryCheckerSettings::ownKeyThreshold() const
{
    return d->ownKeyThreshold;
}

void ExpiryCheckerSettings::setOtherKeyThreshold(Kleo::chrono::days threshold)
{
    d->otherKeyThreshold = threshold;
}

Kleo::chrono::days ExpiryCheckerSettings::otherKeyThreshold() const
{
    return d->otherKeyThreshold;
}

void ExpiryCheckerSettings::setRootCertThreshold(Kleo::chrono::days threshold)
{
    d->rootCertThreshold = threshold;
}

Kleo::chrono::days ExpiryCheckerSettings::rootCertThreshold() const
{
    return d->rootCertThreshold;
}

void ExpiryCheckerSettings::setChainCertThreshold(Kleo::chrono::days threshold)
{
    d->chainCertThreshold = threshold;
}

Kleo::chrono::days ExpiryCheckerSettings::chainCertThreshold() const
{
    return d->chainCertThreshold;
}
