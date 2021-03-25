/*
    autotests/keyresolvercoretest.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <Libkleo/KeyCache>
#include <Libkleo/KeyResolverCore>

#include <QObject>
#include <QTest>

#include <gpgme++/key.h>

#include <memory>

using namespace Kleo;
using namespace GpgME;

class KeyResolverCoreTest: public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void init()
    {
        mGnupgHome = QTest::qExtractTestData("/fixtures/keyresolvercoretest");
        qputenv("GNUPGHOME", mGnupgHome->path().toLocal8Bit());

        // hold a reference to the key cache to avoid rebuilding while the test is running
        mKeyCache = KeyCache::instance();
    }

    void cleanup()
    {
        // verify that nobody else holds a reference to the key cache
        QVERIFY(mKeyCache.use_count() == 1);
        mKeyCache.reset();

        mGnupgHome.reset();
    }

    void test_verify_test_keys()
    {
        {
            const Key openpgp = testKey("sender-mixed@example.net", OpenPGP);
            QVERIFY(openpgp.hasSecret() && openpgp.canEncrypt() && openpgp.canSign());
            QCOMPARE(openpgp.userID(0).validity(), UserID::Ultimate);
            const Key smime = testKey("sender-mixed@example.net", CMS);
            QVERIFY(smime.hasSecret() && smime.canEncrypt() && smime.canSign());
            QCOMPARE(smime.userID(0).validity(), UserID::Ultimate);
        }
        {
            const Key openpgp = testKey("sender-openpgp@example.net", OpenPGP);
            QVERIFY(openpgp.hasSecret() && openpgp.canEncrypt() && openpgp.canSign());
            QCOMPARE(openpgp.userID(0).validity(), UserID::Ultimate);
        }
        {
            const Key openpgp = testKey("prefer-openpgp@example.net", OpenPGP);
            QVERIFY(openpgp.canEncrypt());
            QCOMPARE(openpgp.userID(0).validity(), UserID::Full);
        }
        {
            const Key openpgp = testKey("prefer-smime@example.net", OpenPGP);
            QVERIFY(openpgp.canEncrypt());
            QCOMPARE(openpgp.userID(0).validity(), UserID::Marginal);
            const Key smime = testKey("prefer-smime@example.net", CMS);
            QVERIFY(smime.canEncrypt());
            QVERIFY(smime.userID(0).validity() >= UserID::Full);
        }
    }

    void test_openpgp_is_used_if_openpgp_only_and_smime_only_are_both_possible()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.signingKeys().value(OpenPGP).size(), 1);
        QCOMPARE(resolver.signingKeys().value(OpenPGP)[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(resolver.signingKeys().value(CMS).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("sender-mixed@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("sender-mixed@example.net")[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(resolver.encryptionKeys().value(CMS).size(), 0);
    }

    void test_openpgp_is_used_if_openpgp_only_and_smime_only_are_both_possible_with_preference_for_openpgp()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setPreferredProtocol(OpenPGP);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.signingKeys().value(OpenPGP).size(), 1);
        QCOMPARE(resolver.signingKeys().value(OpenPGP)[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(resolver.signingKeys().value(CMS).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("sender-mixed@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("sender-mixed@example.net")[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(resolver.encryptionKeys().value(CMS).size(), 0);
    }

    void test_smime_is_used_if_openpgp_only_and_smime_only_are_both_possible_with_preference_for_smime()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setPreferredProtocol(CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.signingKeys().value(OpenPGP).size(), 0);
        QCOMPARE(resolver.signingKeys().value(CMS).size(), 1);
        QCOMPARE(resolver.signingKeys().value(CMS)[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", CMS).primaryFingerprint());
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(CMS).size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("sender-mixed@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("sender-mixed@example.net")[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", CMS).primaryFingerprint());
    }

    void test_overrides_openpgp()
    {
        const QString override = testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setOverrideKeys({{OpenPGP, {{QStringLiteral("Needs to be normalized <sender-mixed@example.net>"), {override}}}}});

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("sender-mixed@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("sender-mixed@example.net")[0].primaryFingerprint(), override);
    }

    void test_overrides_smime()
    {
        const QString override = testKey("prefer-smime@example.net", CMS).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setPreferredProtocol(CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setOverrideKeys({{CMS, {{QStringLiteral("Needs to be normalized <sender-mixed@example.net>"), {override}}}}});

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.encryptionKeys().value(CMS).size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("sender-mixed@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("sender-mixed@example.net")[0].primaryFingerprint(), override);
    }

private:
    Key testKey(const char *email, Protocol protocol = UnknownProtocol)
    {
        const std::vector<Key> keys = KeyCache::instance()->findByEMailAddress(email);
        for (const auto &key: keys) {
            if (protocol == UnknownProtocol || key.protocol() == protocol) {
                return key;
            }
        }
        return Key();
    }

private:
    QSharedPointer<QTemporaryDir> mGnupgHome;
    std::shared_ptr<const KeyCache> mKeyCache;
};

QTEST_MAIN(KeyResolverCoreTest)
#include "keyresolvercoretest.moc"
