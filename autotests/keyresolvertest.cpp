/*
    autotests/keyresolvertest.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <Libkleo/KeyCache>
#include <Libkleo/KeyResolver>

#include <QObject>
#include <QSignalSpy>
#include <QTest>

#include <gpgme++/key.h>

#include <memory>

using namespace Kleo;
using namespace GpgME;

class KeyResolverTest: public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void init()
    {
        mGnupgHome = QTest::qExtractTestData("/fixtures/keyresolvertest");
        qputenv("GNUPGHOME", mGnupgHome->path().toLocal8Bit());

        // hold a reference to the key cache to avoid rebuilding while the test is running
        mKeyCache = KeyCache::instance();
    }

    void cleanup()
    {
        mKeysResolvedSpy.reset();

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
        KeyResolver resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        spyOnKeysResolvedSignal(&resolver);

        resolver.start(/*showApproval=*/ false);

        verifyKeysResolvedSignalEmittedWith(/*success=*/ true, /*sendUnencrypted=*/ false);
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
        KeyResolver resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setPreferredProtocol(OpenPGP);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        spyOnKeysResolvedSignal(&resolver);

        resolver.start(/*showApproval=*/ false);

        verifyKeysResolvedSignalEmittedWith(/*success=*/ true, /*sendUnencrypted=*/ false);
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
        KeyResolver resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setPreferredProtocol(CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        spyOnKeysResolvedSignal(&resolver);

        resolver.start(/*showApproval=*/ false);

        verifyKeysResolvedSignalEmittedWith(/*success=*/ true, /*sendUnencrypted=*/ false);
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

    void test_override_sender_openpgp()
    {
        const QString override = testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint();
        KeyResolver resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setOverrideKeys({{OpenPGP, {{QStringLiteral("sender-mixed@example.net"), {override}}}}});
        spyOnKeysResolvedSignal(&resolver);

        resolver.start(/*showApproval=*/ false);

        verifyKeysResolvedSignalEmittedWith(/*success=*/ true, /*sendUnencrypted=*/ false);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("sender-mixed@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("sender-mixed@example.net")[0].primaryFingerprint(), override);
    }

    void test_override_sender_smime()
    {
        const QString override = testKey("prefer-smime@example.net", CMS).primaryFingerprint();
        KeyResolver resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setPreferredProtocol(CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setOverrideKeys({{CMS, {{QStringLiteral("sender-mixed@example.net"), {override}}}}});
        spyOnKeysResolvedSignal(&resolver);

        resolver.start(/*showApproval=*/ false);

        verifyKeysResolvedSignalEmittedWith(/*success=*/ true, /*sendUnencrypted=*/ false);
        QCOMPARE(resolver.encryptionKeys().value(CMS).size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("sender-mixed@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("sender-mixed@example.net")[0].primaryFingerprint(), override);
    }

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

    void spyOnKeysResolvedSignal(KeyResolver *resolver)
    {
        mKeysResolvedSpy = std::make_unique<QSignalSpy>(resolver, &KeyResolver::keysResolved);
        QVERIFY(mKeysResolvedSpy->isValid());
    }

    void verifyKeysResolvedSignalEmittedWith(bool success, bool sendUnencrypted)
    {
        QCOMPARE(mKeysResolvedSpy->count(), 1);
        const QList<QVariant> arguments = mKeysResolvedSpy->takeFirst();
        QCOMPARE(arguments.at(0).toBool(), success);
        QCOMPARE(arguments.at(1).toBool(), sendUnencrypted);
    }

private:
    QSharedPointer<QTemporaryDir> mGnupgHome;
    std::shared_ptr<const KeyCache> mKeyCache;
    std::unique_ptr<QSignalSpy> mKeysResolvedSpy;
};

QTEST_MAIN(KeyResolverTest)
#include "keyresolvertest.moc"
