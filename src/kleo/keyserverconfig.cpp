/*
    kleo/keyserverconfig.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "keyserverconfig.h"

#include "utils/algorithm.h"

#include <QString>
#include <QUrl>

using namespace Kleo;

class KeyserverConfig::Private
{
public:
    explicit Private();

    QString host;
    int port = -1;  // -1 == use default port
    KeyserverAuthentication authentication = KeyserverAuthentication::Anonymous;
    QString user;
    QString password;
    KeyserverConnection connection = KeyserverConnection::Default;
    QString baseDn;
    QStringList additionalFlags;
};

KeyserverConfig::Private::Private()
{
}

KeyserverConfig::KeyserverConfig()
    : d{std::make_unique<Private>()}
{
}

KeyserverConfig::~KeyserverConfig() = default;

KeyserverConfig::KeyserverConfig(const KeyserverConfig &other)
    : d{std::make_unique<Private>(*other.d)}
{
}

KeyserverConfig &KeyserverConfig::operator=(const KeyserverConfig &other)
{
    *d = *other.d;
    return *this;
}

KeyserverConfig::KeyserverConfig(KeyserverConfig &&other) = default;

KeyserverConfig &KeyserverConfig::operator=(KeyserverConfig &&other) = default;

KeyserverConfig KeyserverConfig::fromUrl(const QUrl &url)
{
    KeyserverConfig config;

    config.d->host = url.host();
    config.d->port = url.port();
    config.d->user = url.userName();
    config.d->password = url.password();
    if (!config.d->user.isEmpty()) {
        config.d->authentication = KeyserverAuthentication::Password;
    }
    if (url.hasFragment()) {
        const auto flags = transformInPlace(url.fragment().split(QLatin1Char{','}, Qt::SkipEmptyParts),
                                            [] (const auto &flag) { return flag.trimmed().toLower(); });
        for (const auto &flag : flags) {
            if (flag == QLatin1String{"starttls"}) {
                config.d->connection = KeyserverConnection::UseSTARTTLS;
            } else if (flag == QLatin1String{"ldaptls"}) {
                config.d->connection = KeyserverConnection::TunnelThroughTLS;
            } else if (flag == QLatin1String{"plain"}) {
                config.d->connection = KeyserverConnection::Plain;
            } else if (flag == QLatin1String{"ntds"}) {
                config.d->authentication = KeyserverAuthentication::ActiveDirectory;
            } else {
                config.d->additionalFlags.push_back(flag);
            }
        }
    }
    if (url.hasQuery()) {
        config.d->baseDn = url.query();
    }

    return config;
}

QUrl KeyserverConfig::toUrl() const
{
    QUrl url;

    url.setScheme(QStringLiteral("ldap"));
    // set host to empty string if it's a null string; this ensures that the URL has an authority and always gets a "//" after the scheme
    url.setHost(d->host.isNull() ? QStringLiteral("") : d->host);
    if (d->port != -1) {
        url.setPort(d->port);
    }
    if (!d->user.isEmpty()) {
        url.setUserName(d->user);
    }
    if (!d->password.isEmpty()) {
        url.setPassword(d->password);
    }
    if (!d->baseDn.isEmpty()) {
        url.setQuery(d->baseDn);
    }

    QStringList flags;
    switch (d->connection) {
    case KeyserverConnection::UseSTARTTLS:
        flags.push_back(QStringLiteral("starttls"));
        break;
    case KeyserverConnection::TunnelThroughTLS:
        flags.push_back(QStringLiteral("ldaptls"));
        break;
    case KeyserverConnection::Plain:
        flags.push_back(QStringLiteral("plain"));
        break;
    case KeyserverConnection::Default:
        ; // omit connection flag to use default
    }
    if (d->authentication == KeyserverAuthentication::ActiveDirectory) {
        flags.push_back(QStringLiteral("ntds"));
    }
    std::copy(std::cbegin(d->additionalFlags), std::cend(d->additionalFlags), std::back_inserter(flags));
    if (!flags.isEmpty()) {
        url.setFragment(flags.join(QLatin1Char{','}));
    }

    return url;
}

QString KeyserverConfig::host() const
{
    return d->host;
}

void KeyserverConfig::setHost(const QString &host)
{
    d->host = host;
}

int KeyserverConfig::port() const
{
    return d->port;
}

void KeyserverConfig::setPort(int port)
{
    d->port = port;
}

KeyserverAuthentication KeyserverConfig::authentication() const
{
    return d->authentication;
}

void KeyserverConfig::setAuthentication(KeyserverAuthentication authentication)
{
    d->authentication = authentication;
}

QString KeyserverConfig::user() const
{
    return d->user;
}

void KeyserverConfig::setUser(const QString &user)
{
    d->user = user;
}

QString KeyserverConfig::password() const
{
    return d->password;
}

void KeyserverConfig::setPassword(const QString &password)
{
    d->password = password;
}

KeyserverConnection KeyserverConfig::connection() const
{
    return d->connection;
}

void KeyserverConfig::setConnection(KeyserverConnection connection)
{
    d->connection = connection;
}

QString KeyserverConfig::ldapBaseDn() const
{
    return d->baseDn;
}

void KeyserverConfig::setLdapBaseDn(const QString &baseDn)
{
    d->baseDn = baseDn;
}

QStringList KeyserverConfig::additionalFlags() const
{
    return d->additionalFlags;
}

void KeyserverConfig::setAdditionalFlags(const QStringList &flags)
{
    d->additionalFlags = flags;
}
