/*
    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "expirycheckerconfig.h"

#include "expirycheckersettings.h"

using namespace Kleo;

ExpiryCheckerSettings ExpiryCheckerConfig::settings() const
{
    using days = Kleo::chrono::days;
    return ExpiryCheckerSettings{days{ownKeyThresholdInDays()},
                                 days{otherKeyThresholdInDays()},
                                 days{rootCertificateThresholdInDays()},
                                 days{intermediateCertificateThresholdInDays()}};
}

const KConfigSkeletonItem *ExpiryCheckerConfig::ownKeyThresholdInDaysItem() const
{
    return findItem(QStringLiteral("ownKeyThresholdInDays"));
}

const KConfigSkeletonItem *ExpiryCheckerConfig::otherKeyThresholdInDaysItem() const
{
    return findItem(QStringLiteral("otherKeyThresholdInDays"));
}

const KConfigSkeletonItem *ExpiryCheckerConfig::rootCertificateThresholdInDaysItem() const
{
    return findItem(QStringLiteral("rootCertificateThresholdInDays"));
}

const KConfigSkeletonItem *ExpiryCheckerConfig::intermediateCertificateThresholdInDaysItem() const
{
    return findItem(QStringLiteral("intermediateCertificateThresholdInDays"));
}
