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
        qDebug() << "Using GNUPGHOME" << qgetenv("GNUPGHOME");

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
            const auto keys = KeyCache::instance()->findByEMailAddress("sender-mixed@example.net");
            QCOMPARE(keys.size(), 2);
            QVERIFY((keys[0].protocol() == OpenPGP && keys[1].protocol() == CMS) ||
                    (keys[1].protocol() == OpenPGP && keys[0].protocol() == CMS));
            QVERIFY(keys[0].hasSecret() && keys[0].canEncrypt() && keys[0].canSign());
            QCOMPARE(keys[0].userID(0).validity(), UserID::Ultimate);
            QVERIFY(keys[1].hasSecret() && keys[1].canEncrypt() && keys[1].canSign());
            QCOMPARE(keys[1].userID(0).validity(), UserID::Ultimate);
        }
        {
            const auto keys = KeyCache::instance()->findByEMailAddress("sender-openpgp@example.net");
            QCOMPARE(keys.size(), 1);
            QVERIFY(keys[0].protocol() == OpenPGP);
            QVERIFY(keys[0].hasSecret() && keys[0].canEncrypt() && keys[0].canSign());
            QCOMPARE(keys[0].userID(0).validity(), UserID::Ultimate);
        }
        {
            const auto keys = KeyCache::instance()->findByEMailAddress("prefer-openpgp@example.net");
            QCOMPARE(keys.size(), 1);
            QVERIFY(keys[0].protocol() == OpenPGP);
            QVERIFY(keys[0].canEncrypt());
            QCOMPARE(keys[0].userID(0).validity(), UserID::Full);
        }
        {
            const auto keys = KeyCache::instance()->findByEMailAddress("prefer-smime@example.net");
            QCOMPARE(keys.size(), 2);
            const Key openpgp = keys[0].protocol() == OpenPGP ? keys[0] : keys[1];
            QVERIFY(openpgp.protocol() == OpenPGP);
            QVERIFY(openpgp.canEncrypt());
            QCOMPARE(openpgp.userID(0).validity(), UserID::Marginal);
            const Key smime = keys[0].protocol() == CMS ? keys[0] : keys[1];
            QVERIFY(smime.protocol() == CMS);
            QVERIFY(smime.canEncrypt());
            QVERIFY(smime.userID(0).validity() >= UserID::Full);
        }
    }

    void test_openpgp_is_preferred_if_openpgp_only_and_smime_only_are_both_possible()
    {
        KeyResolver resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        spyOnKeysResolvedSignal(&resolver);

        resolver.start(/*showApproval=*/ false);

        verifyKeysResolvedSignalEmittedWith(/*success=*/ true, /*sendUnencrypted=*/ false);
        QCOMPARE(resolver.signingKeys().value(OpenPGP).size(), 1);
        QCOMPARE(resolver.signingKeys().value(CMS).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("sender-mixed@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(CMS).size(), 0);
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
