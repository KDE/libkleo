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

#include <Libkleo/Chrono>

#include <QDate>
#include <QObject>

#include <gpgme++/key.h>

#include <memory>

namespace Kleo
{

class ExpiryCheckerPrivate;
class ExpiryCheckerSettings;

class KLEO_EXPORT TimeProvider
{
public:
    virtual ~TimeProvider() = default;

    virtual time_t currentTime() const = 0;
    virtual QDate currentDate() const = 0;
    virtual Qt::TimeSpec timeSpec() const = 0;
};

class KLEO_EXPORT ExpiryChecker : public QObject
{
    Q_OBJECT
public:
    enum CheckFlag {
        EncryptionKey = 0x01,
        SigningKey = 0x02,
        CertificationKey = 0x04,
        OwnKey = 0x08,
        OwnEncryptionKey = OwnKey | EncryptionKey,
        OwnSigningKey = OwnKey | SigningKey,
        CheckChain = 0x10,
        UsageMask = EncryptionKey | SigningKey | CertificationKey,
    };
    Q_FLAG(CheckFlag)
    Q_DECLARE_FLAGS(CheckFlags, CheckFlag)
    Q_FLAG(CheckFlags)

    enum ExpirationStatus {
        NotNearExpiry,
        ExpiresSoon,
        Expired,
        NoSuitableSubkey,
        InvalidKey,
        InvalidCheckFlags,
    };
    Q_ENUM(ExpirationStatus)

    struct Expiration {
        GpgME::Key certificate;
        ExpirationStatus status;
        // duration is days until expiry if status is ExpiresSoon (i.e. 0
        // if expiry is today, 1 if it's tomorrow, etc.),
        // days since expiry if status is Expired, and
        // undefined otherwise
        Kleo::chrono::days duration;
    };

    struct Result {
        CheckFlags checkFlags;
        Expiration expiration; // result for the checked certificate
        std::vector<Expiration> chainExpiration; // results for expired or soon expiring chain certificates
    };

    explicit ExpiryChecker(const ExpiryCheckerSettings &settings, QObject *parent = nullptr);

    ~ExpiryChecker() override;

    Q_REQUIRED_RESULT ExpiryCheckerSettings settings() const;

    enum ExpiryInformation {
        OwnKeyExpired,
        OwnKeyNearExpiry,
        OtherKeyExpired,
        OtherKeyNearExpiry,
    };
    Q_ENUM(ExpiryInformation)

    Result checkKey(const GpgME::Key &key, CheckFlags flags) const;

Q_SIGNALS:
    void expiryMessage(const GpgME::Key &key, QString msg, Kleo::ExpiryChecker::ExpiryInformation info, bool isNewMessage) const;

public:
    void setTimeProviderForTest(const std::shared_ptr<TimeProvider> &);

private:
    std::unique_ptr<ExpiryCheckerPrivate> const d;
};

Q_DECLARE_OPERATORS_FOR_FLAGS(ExpiryChecker::CheckFlags)
}
Q_DECLARE_METATYPE(Kleo::ExpiryChecker::CheckFlags)
Q_DECLARE_METATYPE(Kleo::ExpiryChecker::ExpiryInformation)
Q_DECLARE_METATYPE(GpgME::Key)
