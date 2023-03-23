/*
    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2021 Sandro Knauß <sknauss@kde.org>
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    Based on kpgp.h
    Copyright (C) 2001,2002 the KPGP authors
    See file libkdenetwork/AUTHORS.kpgp for details

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QObject>

#include <gpgme++/key.h>

#include <memory>

namespace Kleo
{

class ExpiryCheckerPrivate;

class KLEO_EXPORT TimeProvider
{
public:
    virtual ~TimeProvider() = default;

    virtual time_t getTime() const = 0;
};

class KLEO_EXPORT ExpiryChecker : public QObject
{
    Q_OBJECT
public:
    explicit ExpiryChecker(int encrOwnKeyNearExpiryThresholdDays,
                           int encrKeyNearExpiryThresholdDays,
                           int encrRootCertNearExpiryThresholdDays,
                           int encrChainCertNearExpiryThresholdDays);

    ~ExpiryChecker() override;

    Q_REQUIRED_RESULT int encryptOwnKeyNearExpiryWarningThresholdInDays() const;
    Q_REQUIRED_RESULT int encryptKeyNearExpiryWarningThresholdInDays() const;
    Q_REQUIRED_RESULT int encryptRootCertNearExpiryWarningThresholdInDays() const;
    Q_REQUIRED_RESULT int encryptChainCertNearExpiryWarningThresholdInDays() const;

    enum ExpiryInformation {
        OwnKeyExpired,
        OwnKeyNearExpiry,
        OtherKeyExpired,
        OtherKeyNearExpiry,
    };
    Q_ENUM(ExpiryInformation)

    void checkOwnSigningKey(const GpgME::Key &key) const;
    void checkOwnKey(const GpgME::Key &key) const;
    void checkKey(const GpgME::Key &key) const;

Q_SIGNALS:
    void expiryMessage(const GpgME::Key &key, QString msg, Kleo::ExpiryChecker::ExpiryInformation info, bool isNewMessage) const;

public:
    void setTimeProviderForTest(const std::shared_ptr<TimeProvider> &);

private:
    std::unique_ptr<ExpiryCheckerPrivate> const d;
};
}
Q_DECLARE_METATYPE(GpgME::Key)
