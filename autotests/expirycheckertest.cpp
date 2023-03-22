/*
    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2022 Sandro Knauß <knauss@kde.org>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include "../src/kleo/expirychecker_p.h"

#include <Libkleo/ExpiryChecker>
#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>

#include <QDebug>
#include <QProcess>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>

using namespace Kleo;
using namespace GpgME;

class ExpiryCheckerTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase()
    {
        qRegisterMetaType<ExpiryChecker::ExpiryInformation>();

        mGnupgHome = QTest::qExtractTestData(QStringLiteral("/fixtures/expirycheckertest"));
        qputenv("GNUPGHOME", mGnupgHome->path().toLocal8Bit());

        // hold a reference to the key cache to avoid rebuilding while the test is running
        mKeyCache = KeyCache::instance();
        // make sure that the key cache has been populated
        (void)mKeyCache->keys();
    }

    void cleanupTestCase()
    {
        // verify that nobody else holds a reference to the key cache
        QVERIFY(mKeyCache.use_count() == 1);
        mKeyCache.reset();

        (void)QProcess::execute(QStringLiteral("gpgconf"), {"--kill", "all"});

        mGnupgHome.reset();
        qunsetenv("GNUPGHOME");
    }

    void valid_data()
    {
        QTest::addColumn<GpgME::Key>("key");
        QTest::addColumn<int>("difftime");
        QTest::newRow("neverExpire") << testKey("test@kolab.org", GpgME::OpenPGP) << -1;
        QTest::newRow("openpgp") << testKey("alice@autocrypt.example", GpgME::OpenPGP) << 2 * 24 * 60 * 60;
        QTest::newRow("smime") << testKey("test@example.com", GpgME::CMS) << 2 * 24 * 60 * 60;
    }

    void valid()
    {
        QFETCH(GpgME::Key, key);
        QFETCH(int, difftime);

        ExpiryChecker checker(1, 1, 1, 1);
        QSignalSpy spy(&checker, &ExpiryChecker::expiryMessage);
        checker.d->testMode = true;
        checker.d->difftime = difftime;

        checker.checkKey(key);
        QCOMPARE(spy.count(), 0);
    }

    void expired_data()
    {
        QTest::addColumn<GpgME::Key>("key");
        QTest::addColumn<QString>("msg");
        QTest::addColumn<QString>("msgOwnKey");
        QTest::addColumn<QString>("msgOwnSigningKey");

        QTest::newRow("openpgp")
            << testKey("alice@autocrypt.example", GpgME::OpenPGP)
            << QStringLiteral(
                   "<p>The OpenPGP key for</p><p align=center><b>alice@autocrypt.example</b> (KeyID 0xF231550C4F47E38E)</p><p>expired less than a day ago.</p>")
            << QStringLiteral(
                   "<p>Your OpenPGP encryption key</p><p align=center><b>alice@autocrypt.example</b> (KeyID 0xF231550C4F47E38E)</p><p>expired less than a day "
                   "ago.</p>")
            << QStringLiteral(
                   "<p>Your OpenPGP signing key</p><p align=center><b>alice@autocrypt.example</b> (KeyID 0xF231550C4F47E38E)</p><p>expired less than a day "
                   "ago.</p>");
        QTest::newRow("smime") << testKey("test@example.com", GpgME::CMS)
                               << QStringLiteral(
                                      "<p>The S/MIME certificate for</p><p align=center><b>CN=unittest cert,EMAIL=test@example.com,O=KDAB,C=US</b> (serial "
                                      "number 00D345203A186385C9)</p><p>expired less than a day ago.</p>")
                               << QStringLiteral(
                                      "<p>Your S/MIME encryption certificate</p><p align=center><b>CN=unittest cert,EMAIL=test@example.com,O=KDAB,C=US</b> "
                                      "(serial number 00D345203A186385C9)</p><p>expired less than a day ago.</p>")
                               << QStringLiteral(
                                      "<p>Your S/MIME signing certificate</p><p align=center><b>CN=unittest cert,EMAIL=test@example.com,O=KDAB,C=US</b> "
                                      "(serial number 00D345203A186385C9)</p><p>expired less than a day ago.</p>");
    }

    void expired()
    {
        QFETCH(GpgME::Key, key);
        QFETCH(QString, msg);
        QFETCH(QString, msgOwnKey);
        QFETCH(QString, msgOwnSigningKey);

        ExpiryChecker checker(1, 1, 1, 1);
        checker.d->testMode = true;
        checker.d->difftime = -1;
        {
            QSignalSpy spy(&checker, &ExpiryChecker::expiryMessage);
            checker.checkKey(key);
            QCOMPARE(spy.count(), 1);
            QList<QVariant> arguments = spy.takeFirst();
            QCOMPARE(arguments.at(0).value<GpgME::Key>().keyID(), key.keyID());
            QCOMPARE(arguments.at(1).toString(), msg);
            QCOMPARE(arguments.at(2).value<ExpiryChecker::ExpiryInformation>(), ExpiryChecker::OtherKeyExpired);
        }
        checker.d->alreadyWarnedFingerprints.clear();
        {
            QSignalSpy spy(&checker, &ExpiryChecker::expiryMessage);
            checker.checkOwnKey(key);
            QCOMPARE(spy.count(), 1);
            QList<QVariant> arguments = spy.takeFirst();
            QCOMPARE(arguments.at(0).value<GpgME::Key>().keyID(), key.keyID());
            QCOMPARE(arguments.at(1).toString(), msgOwnKey);
            QCOMPARE(arguments.at(2).value<ExpiryChecker::ExpiryInformation>(), ExpiryChecker::OwnKeyExpired);
        }
        checker.d->alreadyWarnedFingerprints.clear();
        {
            QSignalSpy spy(&checker, &ExpiryChecker::expiryMessage);
            checker.checkOwnSigningKey(key);
            QCOMPARE(spy.count(), 1);
            QList<QVariant> arguments = spy.takeFirst();
            QCOMPARE(arguments.at(0).value<GpgME::Key>().keyID(), key.keyID());
            QCOMPARE(arguments.at(1).toString(), msgOwnSigningKey);
            QCOMPARE(arguments.at(2).value<ExpiryChecker::ExpiryInformation>(), ExpiryChecker::OwnKeyExpired);
        }
    }

    void nearexpiry_data()
    {
        QTest::addColumn<GpgME::Key>("key");
        QTest::addColumn<QString>("msg");
        QTest::addColumn<QString>("msgOwnKey");
        QTest::addColumn<QString>("msgOwnSigningKey");

        QTest::newRow("openpgp")
            << testKey("alice@autocrypt.example", GpgME::OpenPGP)
            << QStringLiteral(
                   "<p>The OpenPGP key for</p><p align=center><b>alice@autocrypt.example</b> (KeyID 0xF231550C4F47E38E)</p><p>expires in less than 6 days.</p>")
            << QStringLiteral(
                   "<p>Your OpenPGP encryption key</p><p align=center><b>alice@autocrypt.example</b> (KeyID 0xF231550C4F47E38E)</p><p>expires in less than 6 "
                   "days.</p>")
            << QStringLiteral(
                   "<p>Your OpenPGP signing key</p><p align=center><b>alice@autocrypt.example</b> (KeyID 0xF231550C4F47E38E)</p><p>expires in less than 6 "
                   "days.</p>");
        QTest::newRow("smime") << testKey("test@example.com", GpgME::CMS)
                               << QStringLiteral(
                                      "<p>The S/MIME certificate for</p><p align=center><b>CN=unittest cert,EMAIL=test@example.com,O=KDAB,C=US</b> (serial "
                                      "number 00D345203A186385C9);</p><p>expires in less than 6 days.</p>")
                               << QStringLiteral(
                                      "<p>Your S/MIME encryption certificate</p><p align=center><b>CN=unittest cert,EMAIL=test@example.com,O=KDAB,C=US</b> "
                                      "(serial number 00D345203A186385C9);</p><p>expires in less than 6 days.</p>")
                               << QStringLiteral(
                                      "<p>Your S/MIME signing certificate</p><p align=center><b>CN=unittest cert,EMAIL=test@example.com,O=KDAB,C=US</b> "
                                      "(serial number 00D345203A186385C9);</p><p>expires in less than 6 days.</p>");
    }

    void nearexpiry()
    {
        QFETCH(GpgME::Key, key);
        QFETCH(QString, msg);
        QFETCH(QString, msgOwnKey);
        QFETCH(QString, msgOwnSigningKey);

        {
            ExpiryChecker checker(1, 10, 1, 1);
            checker.d->testMode = true;
            checker.d->difftime = 5 * 24 * 3600; // 5 days
            QSignalSpy spy(&checker, &ExpiryChecker::expiryMessage);
            // Test if the correct treshold is taken
            checker.checkKey(key);
            checker.checkOwnKey(key);
            checker.checkOwnSigningKey(key);
            QCOMPARE(spy.count(), 1);
            QList<QVariant> arguments = spy.takeFirst();
            QCOMPARE(arguments.at(0).value<GpgME::Key>().keyID(), key.keyID());
            QCOMPARE(arguments.at(1).toString(), msg);
            QCOMPARE(arguments.at(2).value<ExpiryChecker::ExpiryInformation>(), ExpiryChecker::OtherKeyNearExpiry);
        }
        {
            ExpiryChecker checker(10, 1, 1, 1);
            checker.d->testMode = true;
            checker.d->difftime = 5 * 24 * 3600; // 5 days
            QSignalSpy spy(&checker, &ExpiryChecker::expiryMessage);
            // Test if the correct treshold is taken
            checker.checkKey(key);
            checker.checkOwnKey(key);
            QCOMPARE(spy.count(), 1);
            QList<QVariant> arguments = spy.takeFirst();
            QCOMPARE(arguments.at(0).value<GpgME::Key>().keyID(), key.keyID());
            QCOMPARE(arguments.at(1).toString(), msgOwnKey);
            QCOMPARE(arguments.at(2).value<ExpiryChecker::ExpiryInformation>(), ExpiryChecker::OwnKeyNearExpiry);
        }
        {
            ExpiryChecker checker(10, 1, 1, 1);
            checker.d->testMode = true;
            checker.d->difftime = 5 * 24 * 3600; // 5 days
            QSignalSpy spy(&checker, &ExpiryChecker::expiryMessage);
            // Test if the correct treshold is taken
            checker.checkKey(key);
            checker.checkOwnSigningKey(key);
            QCOMPARE(spy.count(), 1);
            QList<QVariant> arguments = spy.takeFirst();
            QCOMPARE(arguments.at(0).value<GpgME::Key>().keyID(), key.keyID());
            QCOMPARE(arguments.at(1).toString(), msgOwnSigningKey);
            QCOMPARE(arguments.at(2).value<ExpiryChecker::ExpiryInformation>(), ExpiryChecker::OwnKeyNearExpiry);
        }
    }

private:
    Key testKey(const char *email, Protocol protocol = UnknownProtocol)
    {
        const std::vector<Key> keys = KeyCache::instance()->findByEMailAddress(email);
        for (const auto &key : keys) {
            if (protocol == UnknownProtocol || key.protocol() == protocol) {
                return key;
            }
        }
        qWarning() << "No" << Formatting::displayName(protocol) << "test key found for" << email;
        return {};
    }

private:
    QSharedPointer<QTemporaryDir> mGnupgHome;
    std::shared_ptr<const KeyCache> mKeyCache;
};

QTEST_MAIN(ExpiryCheckerTest)
#include "expirycheckertest.moc"
