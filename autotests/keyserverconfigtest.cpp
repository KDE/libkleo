/*
    autotests/keyserverconfigtest.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <Libkleo/KeyserverConfig>

#include <QString>
#include <QTest>
#include <QUrl>

using namespace Kleo;

namespace QTest
{
template <>
inline char *toString(const KeyserverAuthentication &t)
{
    switch (t) {
    case KeyserverAuthentication::Anonymous: return qstrdup("Anonymous");
    case KeyserverAuthentication::ActiveDirectory: return qstrdup("ActiveDirectory");
    case KeyserverAuthentication::Password: return qstrdup("Password");
    default: return qstrdup((std::string("invalid value (") + std::to_string(static_cast<int>(t)) + ")").c_str());
    }
}

template <>
inline char *toString(const KeyserverConnection &t)
{
    switch (t) {
    case KeyserverConnection::Default: return qstrdup("Default");
    case KeyserverConnection::Plain: return qstrdup("Plain");
    case KeyserverConnection::UseSTARTTLS: return qstrdup("UseSTARTTLS");
    case KeyserverConnection::TunnelThroughTLS: return qstrdup("TunnelThroughTLS");
    default: return qstrdup((std::string("invalid value (") + std::to_string(static_cast<int>(t)) + ")").c_str());
    }
}
}

class KeyserverConfigTest: public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void test_ldap_keyserver_on_active_directory()
    {
        const QUrl url{QStringLiteral("ldap://#ntds")};
        auto config = KeyserverConfig::fromUrl(url);
        QVERIFY(config.host().isEmpty());
        QCOMPARE(config.port(), -1);
        QVERIFY(config.user().isEmpty());
        QVERIFY(config.password().isEmpty());
        QCOMPARE(config.authentication(), KeyserverAuthentication::ActiveDirectory);
        QCOMPARE(config.connection(), KeyserverConnection::Default);
        QVERIFY(config.ldapBaseDn().isEmpty());

        const auto createdUrl = config.toUrl();
        QCOMPARE(createdUrl, url);
        QVERIFY(!createdUrl.hasQuery());
        QVERIFY(createdUrl.hasFragment());
    }

    void test_ldap_keyserver_with_authentication_via_active_directory()
    {
        const QUrl url{QStringLiteral("ldap://ldap.example.net#ntds")};
        auto config = KeyserverConfig::fromUrl(url);
        QCOMPARE(config.host(), QLatin1String("ldap.example.net"));
        QCOMPARE(config.port(), -1);
        QVERIFY(config.user().isEmpty());
        QVERIFY(config.password().isEmpty());
        QCOMPARE(config.authentication(), KeyserverAuthentication::ActiveDirectory);
        QCOMPARE(config.connection(), KeyserverConnection::Default);
        QVERIFY(config.ldapBaseDn().isEmpty());

        const auto createdUrl = config.toUrl();
        QCOMPARE(createdUrl, url);
        QVERIFY(!createdUrl.hasQuery());
        QVERIFY(createdUrl.hasFragment());
    }

    void test_anonymous_ldap_keyserver()
    {
        const QUrl url{QStringLiteral("ldap://ldap.example.net")};
        auto config = KeyserverConfig::fromUrl(url);
        QCOMPARE(config.host(), QLatin1String("ldap.example.net"));
        QCOMPARE(config.port(), -1);
        QVERIFY(config.user().isEmpty());
        QVERIFY(config.password().isEmpty());
        QCOMPARE(config.authentication(), KeyserverAuthentication::Anonymous);
        QCOMPARE(config.connection(), KeyserverConnection::Default);
        QVERIFY(config.ldapBaseDn().isEmpty());

        const auto createdUrl = config.toUrl();
        QCOMPARE(createdUrl, url);
        QVERIFY(!createdUrl.hasQuery());
        QVERIFY(!createdUrl.hasFragment());
    }

    void test_ldap_keyserver_with_password_authentication()
    {
        const QUrl url{QStringLiteral("ldap://user:password@ldap.example.net")};
        auto config = KeyserverConfig::fromUrl(url);
        QCOMPARE(config.host(), QLatin1String("ldap.example.net"));
        QCOMPARE(config.port(), -1);
        QCOMPARE(config.user(), QLatin1String("user"));
        QCOMPARE(config.password(), QLatin1String("password"));
        QCOMPARE(config.authentication(), KeyserverAuthentication::Password);
        QCOMPARE(config.connection(), KeyserverConnection::Default);
        QVERIFY(config.ldapBaseDn().isEmpty());

        const auto createdUrl = config.toUrl();
        QCOMPARE(createdUrl, url);
        QVERIFY(!createdUrl.hasQuery());
        QVERIFY(!createdUrl.hasFragment());
    }

    void test_ldap_keyserver_with_starttls()
    {
        const QUrl url{QStringLiteral("ldap://user:password@ldap.example.net#starttls")};
        auto config = KeyserverConfig::fromUrl(url);
        QCOMPARE(config.host(), QLatin1String("ldap.example.net"));
        QCOMPARE(config.port(), -1);
        QCOMPARE(config.user(), QLatin1String("user"));
        QCOMPARE(config.password(), QLatin1String("password"));
        QCOMPARE(config.authentication(), KeyserverAuthentication::Password);
        QCOMPARE(config.connection(), KeyserverConnection::UseSTARTTLS);
        QVERIFY(config.ldapBaseDn().isEmpty());

        const auto createdUrl = config.toUrl();
        QCOMPARE(createdUrl, url);
        QVERIFY(!createdUrl.hasQuery());
        QVERIFY(createdUrl.hasFragment());
    }

    void test_ldap_keyserver_with_tls_secured_tunnel()
    {
        const QUrl url{QStringLiteral("ldap://user:password@ldap.example.net#ldaptls")};
        auto config = KeyserverConfig::fromUrl(url);
        QCOMPARE(config.host(), QLatin1String("ldap.example.net"));
        QCOMPARE(config.port(), -1);
        QCOMPARE(config.user(), QLatin1String("user"));
        QCOMPARE(config.password(), QLatin1String("password"));
        QCOMPARE(config.authentication(), KeyserverAuthentication::Password);
        QCOMPARE(config.connection(), KeyserverConnection::TunnelThroughTLS);
        QVERIFY(config.ldapBaseDn().isEmpty());

        const auto createdUrl = config.toUrl();
        QCOMPARE(createdUrl, url);
        QVERIFY(!createdUrl.hasQuery());
        QVERIFY(createdUrl.hasFragment());
    }

    void test_ldap_keyserver_with_explicit_plain_connection()
    {
        const QUrl url{QStringLiteral("ldap://user:password@ldap.example.net#plain")};
        auto config = KeyserverConfig::fromUrl(url);
        QCOMPARE(config.host(), QLatin1String("ldap.example.net"));
        QCOMPARE(config.port(), -1);
        QCOMPARE(config.user(), QLatin1String("user"));
        QCOMPARE(config.password(), QLatin1String("password"));
        QCOMPARE(config.authentication(), KeyserverAuthentication::Password);
        QCOMPARE(config.connection(), KeyserverConnection::Plain);
        QVERIFY(config.ldapBaseDn().isEmpty());

        const auto createdUrl = config.toUrl();
        QCOMPARE(createdUrl, url);
        QVERIFY(!createdUrl.hasQuery());
        QVERIFY(createdUrl.hasFragment());
    }

    void test_ldap_keyserver_with_multiple_connection_flags()
    {
        // the last flag wins (as in dirmngr/ldapserver.c)
        const QUrl url{QStringLiteral("ldap://user:password@ldap.example.net#starttls,plain")};
        auto config = KeyserverConfig::fromUrl(url);
        QCOMPARE(config.host(), QLatin1String("ldap.example.net"));
        QCOMPARE(config.port(), -1);
        QCOMPARE(config.user(), QLatin1String("user"));
        QCOMPARE(config.password(), QLatin1String("password"));
        QCOMPARE(config.authentication(), KeyserverAuthentication::Password);
        QCOMPARE(config.connection(), KeyserverConnection::Plain);
        QVERIFY(config.ldapBaseDn().isEmpty());

        const auto createdUrl = config.toUrl();
        // only one connection flag is added
        const auto expectedUrl = QUrl{QStringLiteral("ldap://user:password@ldap.example.net#plain")};
        QCOMPARE(createdUrl, expectedUrl);
        QVERIFY(!createdUrl.hasQuery());
        QVERIFY(createdUrl.hasFragment());
    }

    void test_ldap_keyserver_with_not_normalized_flags()
    {
        const QUrl url{QStringLiteral("ldap://ldap.example.net#startTLS, NTDS")};
        auto config = KeyserverConfig::fromUrl(url);
        QCOMPARE(config.authentication(), KeyserverAuthentication::ActiveDirectory);
        QCOMPARE(config.connection(), KeyserverConnection::UseSTARTTLS);

        const auto createdUrl = config.toUrl();
        const auto expectedUrl = QUrl{QStringLiteral("ldap://ldap.example.net#starttls,ntds")};
        QCOMPARE(createdUrl, expectedUrl);
        QVERIFY(!createdUrl.hasQuery());
        QVERIFY(createdUrl.hasFragment());
    }

    void test_ldap_keyserver_with_explicit_port()
    {
        const QUrl url{QStringLiteral("ldap://user:password@ldap.example.net:4242")};
        auto config = KeyserverConfig::fromUrl(url);
        QCOMPARE(config.host(), QLatin1String("ldap.example.net"));
        QCOMPARE(config.port(), 4242);
        QCOMPARE(config.user(), QLatin1String("user"));
        QCOMPARE(config.password(), QLatin1String("password"));
        QCOMPARE(config.authentication(), KeyserverAuthentication::Password);
        QCOMPARE(config.connection(), KeyserverConnection::Default);
        QVERIFY(config.ldapBaseDn().isEmpty());

        const auto createdUrl = config.toUrl();
        QCOMPARE(createdUrl, url);
        QVERIFY(!createdUrl.hasQuery());
        QVERIFY(!createdUrl.hasFragment());
    }

    void test_ldap_keyserver_with_base_dn()
    {
        const QUrl url{QStringLiteral("ldap://user:password@ldap.example.net?base_dn")};
        auto config = KeyserverConfig::fromUrl(url);
        QCOMPARE(config.host(), QLatin1String("ldap.example.net"));
        QCOMPARE(config.port(), -1);
        QCOMPARE(config.user(), QLatin1String("user"));
        QCOMPARE(config.password(), QLatin1String("password"));
        QCOMPARE(config.authentication(), KeyserverAuthentication::Password);
        QCOMPARE(config.connection(), KeyserverConnection::Default);
        QCOMPARE(config.ldapBaseDn(), QLatin1String("base_dn"));

        const auto createdUrl = config.toUrl();
        QCOMPARE(createdUrl, url);
        QVERIFY(createdUrl.hasQuery());
        QVERIFY(!createdUrl.hasFragment());
    }

    void test_url_with_empty_string_as_user_and_password()
    {
        KeyserverConfig config;
        config.setHost(QStringLiteral("anonymous.example.net"));
        config.setUser(QStringLiteral(""));
        config.setPassword(QStringLiteral(""));

        const auto createdUrl = config.toUrl();
        QCOMPARE(createdUrl, QUrl{QStringLiteral("ldap://anonymous.example.net")});
        QVERIFY(!createdUrl.hasQuery());
        QVERIFY(!createdUrl.hasFragment());
    }

    void test_ldap_keyserver_with_additional_flags()
    {
        const QUrl url{QStringLiteral("ldap://ldap.example.net#flag1,StartTLS, Flag2 ,NTDS,flag 3")};
        auto config = KeyserverConfig::fromUrl(url);
        QCOMPARE(config.authentication(), KeyserverAuthentication::ActiveDirectory);
        QCOMPARE(config.connection(), KeyserverConnection::UseSTARTTLS);
        const QStringList expectedFlags{"flag1", "flag2", "flag 3"};
        QCOMPARE(config.additionalFlags(), expectedFlags);

        const auto createdUrl = config.toUrl();
        const auto expectedUrl = QUrl{QStringLiteral("ldap://ldap.example.net#starttls,ntds,flag1,flag2,flag 3")};
        QCOMPARE(createdUrl, expectedUrl);
        QVERIFY(!createdUrl.hasQuery());
        QVERIFY(createdUrl.hasFragment());
    }
};

QTEST_MAIN(KeyserverConfigTest)
#include "keyserverconfigtest.moc"
