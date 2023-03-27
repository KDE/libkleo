/*
    kleo/expirycheckersettings.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <Libkleo/Chrono>

#include <QtGlobal>

#include <memory>

namespace Kleo
{

class KLEO_EXPORT ExpiryCheckerSettings
{
public:
    ExpiryCheckerSettings(Kleo::chrono::days ownKeyThreshold,
                          Kleo::chrono::days otherKeyThreshold,
                          Kleo::chrono::days rootCertThreshold,
                          Kleo::chrono::days chainCertThreshold);
    ~ExpiryCheckerSettings();

    ExpiryCheckerSettings(const ExpiryCheckerSettings &other);
    ExpiryCheckerSettings &operator=(const ExpiryCheckerSettings &other);

    ExpiryCheckerSettings(ExpiryCheckerSettings &&other);
    ExpiryCheckerSettings &operator=(ExpiryCheckerSettings &&other);

    void setOwnKeyThreshold(Kleo::chrono::days threshold);
    Q_REQUIRED_RESULT Kleo::chrono::days ownKeyThreshold() const;

    void setOtherKeyThreshold(Kleo::chrono::days threshold);
    Q_REQUIRED_RESULT Kleo::chrono::days otherKeyThreshold() const;

    void setRootCertThreshold(Kleo::chrono::days threshold);
    Q_REQUIRED_RESULT Kleo::chrono::days rootCertThreshold() const;

    void setChainCertThreshold(Kleo::chrono::days threshold);
    Q_REQUIRED_RESULT Kleo::chrono::days chainCertThreshold() const;

private:
    class Private;
    std::unique_ptr<Private> d;
};

}
