/*
    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2022 Sandro Knauß <knauss@kde.org>
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include <Libkleo/Chrono>
#include <Libkleo/ExpiryChecker>
#include <Libkleo/ExpiryCheckerSettings>
#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>

#include <QDebug>
#include <QProcess>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>

using namespace Kleo;
using namespace GpgME;

using days = Kleo::chrono::days;

class FakeTimeProvider : public Kleo::TimeProvider
{
public:
    explicit FakeTimeProvider(const QDate &date)
        : mTime{date.startOfDay(Qt::UTC).toSecsSinceEpoch()}
    {
    }

    time_t getTime() const override
    {
        return mTime;
    }

private:
    time_t mTime;
};

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
        QTest::addColumn<QDate>("fakedate");
        // use dates between creation date and expiration date (if there is one) of the test keys/certificates
        QTest::newRow("neverExpire") << testKey("test@kolab.org", GpgME::OpenPGP) << QDate{2012, 1, 1};
        QTest::newRow("openpgp") << testKey("alice@autocrypt.example", GpgME::OpenPGP) << QDate{2020, 1, 1};
        QTest::newRow("smime") << testKey("test@example.com", GpgME::CMS) << QDate{2012, 1, 1};
    }

    void valid()
    {
        QFETCH(GpgME::Key, key);
        QFETCH(QDate, fakedate);

        ExpiryChecker checker(ExpiryCheckerSettings{days{1}, days{1}, days{1}, days{1}});
        checker.setTimeProviderForTest(std::make_shared<FakeTimeProvider>(fakedate));
        QSignalSpy spy(&checker, &ExpiryChecker::expiryMessage);

        checker.checkKey(key);
        QCOMPARE(spy.count(), 0);
    }

    void expired_data()
    {
        QTest::addColumn<GpgME::Key>("key");
        QTest::addColumn<QDate>("fakedate");
        QTest::addColumn<QString>("msg");
        QTest::addColumn<QString>("msgOwnKey");
        QTest::addColumn<QString>("msgOwnSigningKey");

        // use the day after the expiration date of the test keys/certificates as fake date
        QTest::newRow("openpgp")
            << testKey("alice@autocrypt.example", GpgME::OpenPGP) //
            << QDate{2021, 1, 22}
            << QStringLiteral(
                   "<p>The OpenPGP key for</p><p align=center><b>alice@autocrypt.example</b> (KeyID 0xF231550C4F47E38E)</p><p>expired less than a day ago.</p>")
            << QStringLiteral(
                   "<p>Your OpenPGP encryption key</p><p align=center><b>alice@autocrypt.example</b> (KeyID 0xF231550C4F47E38E)</p><p>expired less than a day "
                   "ago.</p>")
            << QStringLiteral(
                   "<p>Your OpenPGP signing key</p><p align=center><b>alice@autocrypt.example</b> (KeyID 0xF231550C4F47E38E)</p><p>expired less than a day "
                   "ago.</p>");
        QTest::newRow("smime") << testKey("test@example.com", GpgME::CMS) //
                               << QDate{2013, 3, 26}
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
        QFETCH(QDate, fakedate);
        QFETCH(QString, msg);
        QFETCH(QString, msgOwnKey);
        QFETCH(QString, msgOwnSigningKey);

        {
            ExpiryChecker checker(ExpiryCheckerSettings{days{1}, days{1}, days{1}, days{1}});
            checker.setTimeProviderForTest(std::make_shared<FakeTimeProvider>(fakedate));
            QSignalSpy spy(&checker, &ExpiryChecker::expiryMessage);
            checker.checkKey(key);
            QCOMPARE(spy.count(), 1);
            QList<QVariant> arguments = spy.takeFirst();
            QCOMPARE(arguments.at(0).value<GpgME::Key>().keyID(), key.keyID());
            QCOMPARE(arguments.at(1).toString(), msg);
            QCOMPARE(arguments.at(2).value<ExpiryChecker::ExpiryInformation>(), ExpiryChecker::OtherKeyExpired);
        }
        {
            ExpiryChecker checker(ExpiryCheckerSettings{days{1}, days{1}, days{1}, days{1}});
            checker.setTimeProviderForTest(std::make_shared<FakeTimeProvider>(fakedate));
            QSignalSpy spy(&checker, &ExpiryChecker::expiryMessage);
            checker.checkOwnKey(key);
            QCOMPARE(spy.count(), 1);
            QList<QVariant> arguments = spy.takeFirst();
            QCOMPARE(arguments.at(0).value<GpgME::Key>().keyID(), key.keyID());
            QCOMPARE(arguments.at(1).toString(), msgOwnKey);
            QCOMPARE(arguments.at(2).value<ExpiryChecker::ExpiryInformation>(), ExpiryChecker::OwnKeyExpired);
        }
        {
            ExpiryChecker checker(ExpiryCheckerSettings{days{1}, days{1}, days{1}, days{1}});
            checker.setTimeProviderForTest(std::make_shared<FakeTimeProvider>(fakedate));
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
        QTest::addColumn<QDate>("fakedate");
        QTest::addColumn<QString>("msg");
        QTest::addColumn<QString>("msgOwnKey");
        QTest::addColumn<QString>("msgOwnSigningKey");

        // use the day 5 days before the expiration date of the test keys/certificates as fake date
        QTest::newRow("openpgp")
            << testKey("alice@autocrypt.example", GpgME::OpenPGP) //
            << QDate{2021, 1, 16}
            << QStringLiteral(
                   "<p>The OpenPGP key for</p><p align=center><b>alice@autocrypt.example</b> (KeyID 0xF231550C4F47E38E)</p><p>expires in less than 6 days.</p>")
            << QStringLiteral(
                   "<p>Your OpenPGP encryption key</p><p align=center><b>alice@autocrypt.example</b> (KeyID 0xF231550C4F47E38E)</p><p>expires in less than 6 "
                   "days.</p>")
            << QStringLiteral(
                   "<p>Your OpenPGP signing key</p><p align=center><b>alice@autocrypt.example</b> (KeyID 0xF231550C4F47E38E)</p><p>expires in less than 6 "
                   "days.</p>");
        QTest::newRow("smime") << testKey("test@example.com", GpgME::CMS) //
                               << QDate{2013, 3, 20}
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
        QFETCH(QDate, fakedate);
        QFETCH(QString, msg);
        QFETCH(QString, msgOwnKey);
        QFETCH(QString, msgOwnSigningKey);

        {
            ExpiryChecker checker(ExpiryCheckerSettings{days{1}, days{10}, days{1}, days{1}});
            checker.setTimeProviderForTest(std::make_shared<FakeTimeProvider>(fakedate));
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
            ExpiryChecker checker(ExpiryCheckerSettings{days{10}, days{1}, days{1}, days{1}});
            checker.setTimeProviderForTest(std::make_shared<FakeTimeProvider>(fakedate));
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
            ExpiryChecker checker(ExpiryCheckerSettings{days{10}, days{1}, days{1}, days{1}});
            checker.setTimeProviderForTest(std::make_shared<FakeTimeProvider>(fakedate));
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
    // OpenPGP keys
    //
    // pub   rsa2048 2009-11-13 [SC]
    //       1BA323932B3FAA826132C79E8D9860C58F246DE6
    // uid           [ultimate] unittest key (no password) <test@kolab.org>
    // sub   rsa2048 2009-11-13 [E]
    //
    // pub   ed25519 2019-01-22 [SC] [expired: 2021-01-21]
    //       EB85BB5FA33A75E15E944E63F231550C4F47E38E
    // uid           [ expired] alice@autocrypt.example
    //
    // S/MIME certificates
    //
    //           ID: 0x212B49DC
    //          S/N: 00D345203A186385C9
    //        (dec): 15223609549285197257
    //       Issuer: /CN=unittest cert/O=KDAB/C=US/EMail=test@example.com
    //      Subject: /CN=unittest cert/O=KDAB/C=US/EMail=test@example.com
    //     validity: 2010-06-29 13:48:23 through 2013-03-25 13:48:23
    //     key type: rsa1024
    // chain length: unlimited
    //     sha1 fpr: 24:D2:FC:A2:2E:B3:B8:0A:1E:37:71:D1:4C:C6:58:E3:21:2B:49:DC
    //     sha2 fpr: 62:4B:A4:B8:7D:8F:99:AA:6B:46:E3:C8:C5:BE:BF:30:29:B6:EC:4E:CC:7D:1F:9F:A8:39:B6:CE:03:6F:C7:FB

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
