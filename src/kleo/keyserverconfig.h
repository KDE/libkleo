/*
    kleo/keyserverconfig.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <memory>

class QString;
class QStringList;
class QUrl;

namespace Kleo
{

enum class KeyserverAuthentication {
    Anonymous,
    ActiveDirectory,
    Password
};

enum class KeyserverConnection {
    Default,
    Plain,
    UseSTARTTLS,
    TunnelThroughTLS
};

class KLEO_EXPORT KeyserverConfig
{
public:
    KeyserverConfig();
    ~KeyserverConfig();

    KeyserverConfig(const KeyserverConfig &other);
    KeyserverConfig &operator=(const KeyserverConfig &other);

    KeyserverConfig(KeyserverConfig &&other);
    KeyserverConfig &operator=(KeyserverConfig &&other);

    static KeyserverConfig fromUrl(const QUrl &url);
    QUrl toUrl() const;

    QString host() const;
    void setHost(const QString &host);

    int port() const;
    void setPort(int port);

    KeyserverAuthentication authentication() const;
    void setAuthentication(KeyserverAuthentication authentication);

    QString user() const;
    void setUser(const QString &user);

    QString password() const;
    void setPassword(const QString &password);

    KeyserverConnection connection() const;
    void setConnection(KeyserverConnection connection);

    QString ldapBaseDn() const;
    void setLdapBaseDn(const QString &baseDn);

    QStringList additionalFlags() const;
    void setAdditionalFlags(const QStringList &flags);

private:
    class Private;
    std::unique_ptr<Private> d;
};

}
