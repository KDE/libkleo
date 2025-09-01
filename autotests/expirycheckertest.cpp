/*
    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2022 Sandro Knauß <knauss@kde.org>
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include "testhelpers.h"

#include <Libkleo/Chrono>
#include <Libkleo/ExpiryChecker>
#include <Libkleo/ExpiryCheckerSettings>
#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>

#include <QDebug>
#include <QProcess>
#include <QRegularExpression>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>

using namespace Kleo;
using namespace GpgME;

Q_DECLARE_METATYPE(GpgME::Key)

using days = Kleo::chrono::days;

class FakeTimeProvider : public Kleo::TimeProvider
{
public:
    explicit FakeTimeProvider(const QDateTime &dateTime)
        : mCurrentDate{dateTime.date()}
        , mCurrentTime{dateTime.toSecsSinceEpoch()}
    {
    }

    qint64 currentTime() const override
    {
        return mCurrentTime;
    }

    QDate currentDate() const override
    {
        return mCurrentDate;
    }

    QTimeZone timeZone() const override
    {
        // use UTC to avoid test failures caused by "wrong" local timezone
        return QTimeZone{QTimeZone::UTC};
    }

private:
    QDate mCurrentDate;
    qint64 mCurrentTime;
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
        QCOMPARE(mKeyCache.use_count(), 1);
        mKeyCache.reset();

        (void)QProcess::execute(QStringLiteral("gpgconf"), {"--kill", "all"});

        mGnupgHome.reset();
        qunsetenv("GNUPGHOME");
    }

    void errorHandling_data()
    {
        QTest::addColumn<GpgME::Key>("key");
        QTest::addColumn<ExpiryChecker::CheckFlags>("checkFlags");
        QTest::addColumn<ExpiryChecker::ExpirationStatus>("expectedStatus");

        QTest::newRow("invalid key") //
            << GpgME::Key{} //
            << ExpiryChecker::CheckFlags{ExpiryChecker::EncryptionKey} //
            << ExpiryChecker::InvalidKey;
        QTest::newRow("invalid flags - no flags") //
            << testKey("test@kolab.org", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{} //
            << ExpiryChecker::InvalidCheckFlags;
        QTest::newRow("invalid flags - no usage flags") //
            << testKey("test@kolab.org", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::OwnKey | ExpiryChecker::CheckChain} //
            << ExpiryChecker::InvalidCheckFlags;
    }

    void errorHandling()
    {
        QFETCH(GpgME::Key, key);
        QFETCH(ExpiryChecker::CheckFlags, checkFlags);
        QFETCH(ExpiryChecker::ExpirationStatus, expectedStatus);

        ExpiryChecker checker(ExpiryCheckerSettings{days{1}, days{1}, days{1}, days{1}});
        QTest::ignoreMessage(QtWarningMsg, QRegularExpression{QStringLiteral("checkKey called with")});
        const auto result = checker.checkKey(key, checkFlags);
        QCOMPARE(result.expiration.certificate, key);
        QCOMPARE(result.expiration.status, expectedStatus);
    }

    void valid_data()
    {
        QTest::addColumn<GpgME::Key>("key");
        QTest::addColumn<QDateTime>("fakedate");
        // use dates between creation date and expiration date (if there is one) of the test keys/certificates
        QTest::newRow("neverExpire") << testKey("test@kolab.org", GpgME::OpenPGP) << QDateTime{{2012, 1, 1}, {}, QTimeZone::UTC};
        QTest::newRow("openpgp") << testKey("alice@autocrypt.example", GpgME::OpenPGP) << QDateTime{{2020, 1, 1}, {}, QTimeZone::UTC};
        QTest::newRow("smime") << testKey("test@example.com", GpgME::CMS) << QDateTime{{2012, 1, 1}, {}, QTimeZone::UTC};
    }

    void valid()
    {
        QFETCH(GpgME::Key, key);
        QFETCH(QDateTime, fakedate);

        ExpiryChecker checker(ExpiryCheckerSettings{days{1}, days{1}, days{1}, days{1}});
        checker.setTimeProviderForTest(std::make_shared<FakeTimeProvider>(fakedate));
        QSignalSpy spy(&checker, &ExpiryChecker::expiryMessage);

        const auto result = checker.checkKey(key, ExpiryChecker::EncryptionKey);
        QCOMPARE(result.checkFlags, ExpiryChecker::EncryptionKey);
        QCOMPARE(result.expiration.certificate, key);
        QCOMPARE(result.expiration.status, ExpiryChecker::NotNearExpiry);
        QCOMPARE(spy.count(), 0);
    }

    void expired_data()
    {
        QTest::addColumn<GpgME::Key>("key");
        QTest::addColumn<ExpiryChecker::CheckFlags>("checkFlags");
        QTest::addColumn<QDateTime>("fakedate");
        QTest::addColumn<Kleo::chrono::days>("expectedDuration");
        QTest::addColumn<ExpiryChecker::ExpiryInformation>("expiryInfo");
        QTest::addColumn<QString>("msg");

        QTest::newRow("openpgp - other; 0 days ago") //
            << testKey("alice@autocrypt.example", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::EncryptionKey} //
            << QDateTime{{2021, 1, 21}, {23, 59, 59}, QTimeZone::UTC} // the last second of the day the key expired
            << days{0} //
            << ExpiryChecker::OtherKeyExpired
            << QStringLiteral(
                   "<p>The OpenPGP key for</p><p align=center><b>alice@autocrypt.example</b> (Key ID 0xF231550C4F47E38E)</p><p>expired less than a day "
                   "ago.</p>");
        QTest::newRow("openpgp - own; 1 day ago") //
            << testKey("alice@autocrypt.example", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::OwnEncryptionKey} //
            << QDateTime{{2021, 1, 22}, {}, QTimeZone::UTC} // the day after the expiration date of the key
            << days{1} //
            << ExpiryChecker::OwnKeyExpired
            << QStringLiteral(
                   "<p>Your OpenPGP encryption key</p><p align=center><b>alice@autocrypt.example</b> (Key ID 0xF231550C4F47E38E)</p><p>expired yesterday.</p>");
        QTest::newRow("openpgp - own signing; 2 days ago") //
            << testKey("alice@autocrypt.example", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::OwnSigningKey} //
            << QDateTime{{2021, 1, 23}, {}, QTimeZone::UTC} // the second day after the expiration date of the key
            << days{2} //
            << ExpiryChecker::OwnKeyExpired
            << QStringLiteral(
                   "<p>Your OpenPGP signing key</p><p align=center><b>alice@autocrypt.example</b> (Key ID 0xF231550C4F47E38E)</p><p>expired 2 days "
                   "ago.</p>");

        QTest::newRow("smime - other; 0 days ago") //
            << testKey("test@example.com", GpgME::CMS) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::EncryptionKey} //
            << QDateTime{{2013, 3, 25}, {23, 59, 59}, QTimeZone::UTC} // the last second of the day the key expired
            << days{0} //
            << ExpiryChecker::OtherKeyExpired
            << QStringLiteral(
                   "<p>The S/MIME certificate for</p><p align=center><b>CN=unittest cert,EMAIL=test@example.com,O=KDAB,C=US</b> (serial "
                   "number 00D345203A186385C9)</p><p>expired less than a day ago.</p>");
        QTest::newRow("smime - own; 1 day ago") //
            << testKey("test@example.com", GpgME::CMS) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::OwnEncryptionKey} //
            << QDateTime{{2013, 3, 26}, {}, QTimeZone::UTC} // the day after the expiration date of the key
            << days{1} //
            << ExpiryChecker::OwnKeyExpired
            << QStringLiteral(
                   "<p>Your S/MIME encryption certificate</p><p align=center><b>CN=unittest cert,EMAIL=test@example.com,O=KDAB,C=US</b> "
                   "(serial number 00D345203A186385C9)</p><p>expired yesterday.</p>");
        QTest::newRow("smime - own signing; 2 days ago") //
            << testKey("test@example.com", GpgME::CMS) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::OwnSigningKey} //
            << QDateTime{{2013, 3, 27}, {}, QTimeZone::UTC} // the second day after the expiration date of the key
            << days{2} //
            << ExpiryChecker::OwnKeyExpired
            << QStringLiteral(
                   "<p>Your S/MIME signing certificate</p><p align=center><b>CN=unittest cert,EMAIL=test@example.com,O=KDAB,C=US</b> "
                   "(serial number 00D345203A186385C9)</p><p>expired 2 days ago.</p>");
    }

    void expired()
    {
        QFETCH(GpgME::Key, key);
        QFETCH(ExpiryChecker::CheckFlags, checkFlags);
        QFETCH(QDateTime, fakedate);
        QFETCH(Kleo::chrono::days, expectedDuration);
        QFETCH(ExpiryChecker::ExpiryInformation, expiryInfo);
        QFETCH(QString, msg);

        {
            ExpiryChecker checker(ExpiryCheckerSettings{days{1}, days{1}, days{1}, days{1}});
            checker.setTimeProviderForTest(std::make_shared<FakeTimeProvider>(fakedate));
            QSignalSpy spy(&checker, &ExpiryChecker::expiryMessage);
            const auto result = checker.checkKey(key, checkFlags);
            QCOMPARE(result.checkFlags, checkFlags);
            QCOMPARE(result.expiration.certificate, key);
            QCOMPARE(result.expiration.status, ExpiryChecker::Expired);
            QCOMPARE(result.expiration.duration, expectedDuration);
            QCOMPARE(spy.count(), 1);
            QList<QVariant> arguments = spy.takeFirst();
            QCOMPARE(arguments.at(0).value<GpgME::Key>().keyID(), key.keyID());
            QCOMPARE(arguments.at(1).toString(), msg);
            QCOMPARE(arguments.at(2).value<ExpiryChecker::ExpiryInformation>(), expiryInfo);
        }
    }

    void nearexpiry_data()
    {
        QTest::addColumn<GpgME::Key>("key");
        QTest::addColumn<QDateTime>("fakedate");
        QTest::addColumn<Kleo::chrono::days>("expectedDuration");
        QTest::addColumn<QString>("msg");
        QTest::addColumn<QString>("msgOwnKey");
        QTest::addColumn<QString>("msgOwnSigningKey");

        // use the day 5 days before the expiration date of the test keys/certificates as fake date
        QTest::newRow("openpgp")
            << testKey("alice@autocrypt.example", GpgME::OpenPGP) //
            << QDateTime{{2021, 1, 16}, {}, QTimeZone::UTC} //
            << days{5}
            << QStringLiteral(
                   "<p>The OpenPGP key for</p><p align=center><b>alice@autocrypt.example</b> (Key ID 0xF231550C4F47E38E)</p><p>expires in 5 days.</p>")
            << QStringLiteral(
                   "<p>Your OpenPGP encryption key</p><p align=center><b>alice@autocrypt.example</b> (Key ID 0xF231550C4F47E38E)</p><p>expires in 5 "
                   "days.</p>")
            << QStringLiteral(
                   "<p>Your OpenPGP signing key</p><p align=center><b>alice@autocrypt.example</b> (Key ID 0xF231550C4F47E38E)</p><p>expires in 5 "
                   "days.</p>");
        QTest::newRow("smime") << testKey("test@example.com", GpgME::CMS) //
                               << QDateTime{{2013, 3, 20}, {}, QTimeZone::UTC} //
                               << days{5}
                               << QStringLiteral(
                                      "<p>The S/MIME certificate for</p><p align=center><b>CN=unittest cert,EMAIL=test@example.com,O=KDAB,C=US</b> (serial "
                                      "number 00D345203A186385C9)</p><p>expires in 5 days.</p>")
                               << QStringLiteral(
                                      "<p>Your S/MIME encryption certificate</p><p align=center><b>CN=unittest cert,EMAIL=test@example.com,O=KDAB,C=US</b> "
                                      "(serial number 00D345203A186385C9)</p><p>expires in 5 days.</p>")
                               << QStringLiteral(
                                      "<p>Your S/MIME signing certificate</p><p align=center><b>CN=unittest cert,EMAIL=test@example.com,O=KDAB,C=US</b> "
                                      "(serial number 00D345203A186385C9)</p><p>expires in 5 days.</p>");
    }

    void nearexpiry()
    {
        QFETCH(GpgME::Key, key);
        QFETCH(QDateTime, fakedate);
        QFETCH(Kleo::chrono::days, expectedDuration);
        QFETCH(QString, msg);
        QFETCH(QString, msgOwnKey);
        QFETCH(QString, msgOwnSigningKey);

        {
            ExpiryChecker checker(ExpiryCheckerSettings{days{1}, days{10}, days{1}, days{1}});
            checker.setTimeProviderForTest(std::make_shared<FakeTimeProvider>(fakedate));
            QSignalSpy spy(&checker, &ExpiryChecker::expiryMessage);
            // Test if the correct threshold is taken
            {
                const auto result = checker.checkKey(key, ExpiryChecker::EncryptionKey);
                QCOMPARE(result.checkFlags, ExpiryChecker::EncryptionKey);
                QCOMPARE(result.expiration.certificate, key);
                QCOMPARE(result.expiration.status, ExpiryChecker::ExpiresSoon);
                QCOMPARE(result.expiration.duration, expectedDuration);
                QCOMPARE(spy.count(), 1);
            }
            {
                const auto result = checker.checkKey(key, ExpiryChecker::OwnEncryptionKey);
                QCOMPARE(result.checkFlags, ExpiryChecker::OwnEncryptionKey);
                QCOMPARE(result.expiration.certificate, key);
                QCOMPARE(result.expiration.status, ExpiryChecker::NotNearExpiry);
                QCOMPARE(result.expiration.duration, expectedDuration);
                QCOMPARE(spy.count(), 1);
            }
            {
                const auto result = checker.checkKey(key, ExpiryChecker::OwnSigningKey);
                QCOMPARE(result.checkFlags, ExpiryChecker::OwnSigningKey);
                QCOMPARE(result.expiration.certificate, key);
                QCOMPARE(result.expiration.status, ExpiryChecker::NotNearExpiry);
                QCOMPARE(result.expiration.duration, expectedDuration);
                QCOMPARE(spy.count(), 1);
            }
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
            checker.checkKey(key, ExpiryChecker::EncryptionKey);
            checker.checkKey(key, ExpiryChecker::OwnEncryptionKey);
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
            checker.checkKey(key, ExpiryChecker::EncryptionKey);
            checker.checkKey(key, ExpiryChecker::OwnSigningKey);
            QCOMPARE(spy.count(), 1);
            QList<QVariant> arguments = spy.takeFirst();
            QCOMPARE(arguments.at(0).value<GpgME::Key>().keyID(), key.keyID());
            QCOMPARE(arguments.at(1).toString(), msgOwnSigningKey);
            QCOMPARE(arguments.at(2).value<ExpiryChecker::ExpiryInformation>(), ExpiryChecker::OwnKeyNearExpiry);
        }
    }

    void expiringEncryptionSubkey_data()
    {
        QTest::addColumn<GpgME::Key>("key");
        QTest::addColumn<ExpiryChecker::CheckFlags>("checkFlags");
        QTest::addColumn<QDateTime>("fakedate");
        QTest::addColumn<ExpiryChecker::ExpirationStatus>("expectedStatus");
        QTest::addColumn<Kleo::chrono::days>("expectedDuration");

        QTest::newRow("valid - sign") //
            << testKey("encr-expires@example.net", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::OwnSigningKey} //
            << QDateTime{{2023, 4, 18}, {}, QTimeZone::UTC} // 9 days before expiration of encryption subkey
            << ExpiryChecker::NotNearExpiry //
            << days{0}; // ignored
        QTest::newRow("valid - encrypt to self") //
            << testKey("encr-expires@example.net", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::OwnEncryptionKey} //
            << QDateTime{{2023, 4, 18}, {}, QTimeZone::UTC} // 9 days before expiration of encryption subkey
            << ExpiryChecker::NotNearExpiry //
            << days{0}; // ignored
        QTest::newRow("valid - encrypt to others") //
            << testKey("encr-expires@example.net", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::EncryptionKey} //
            << QDateTime{{2023, 4, 18}, {}, QTimeZone::UTC} // 9 days before expiration of encryption subkey
            << ExpiryChecker::NotNearExpiry //
            << days{0}; // ignored
        QTest::newRow("near expiry - sign") //
            << testKey("encr-expires@example.net", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::OwnSigningKey} //
            << QDateTime{{2023, 4, 26}, {}, QTimeZone::UTC} // 1 day before expiration of encryption subkey
            << ExpiryChecker::NotNearExpiry // signing key doesn't expire
            << days{0}; // ignored
        QTest::newRow("near expiry - encrypt to self") //
            << testKey("encr-expires@example.net", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::OwnEncryptionKey} //
            << QDateTime{{2023, 4, 26}, {}, QTimeZone::UTC} // 1 day before expiration of encryption subkey
            << ExpiryChecker::ExpiresSoon //
            << days{1};
        QTest::newRow("near expiry - encrypt to others") //
            << testKey("encr-expires@example.net", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::EncryptionKey} //
            << QDateTime{{2023, 4, 26}, {}, QTimeZone::UTC} // 1 day before expiration of encryption subkey
            << ExpiryChecker::ExpiresSoon //
            << days{1};
        QTest::newRow("expired - sign") //
            << testKey("encr-expires@example.net", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::OwnSigningKey} //
            << QDateTime{{2023, 4, 28}, {}, QTimeZone::UTC} // 1 day after expiration of encryption subkey
            << ExpiryChecker::NotNearExpiry // signing key doesn't expire
            << days{0}; // ignored
        QTest::newRow("expired - encrypt to self") //
            << testKey("encr-expires@example.net", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::OwnEncryptionKey} //
            << QDateTime{{2023, 4, 28}, {}, QTimeZone::UTC} // 1 day after expiration of encryption subkey
            << ExpiryChecker::Expired //
            << days{1};
        QTest::newRow("expired - encrypt to others") //
            << testKey("encr-expires@example.net", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::EncryptionKey} //
            << QDateTime{{2023, 4, 28}, {}, QTimeZone::UTC} // 1 day after expiration of encryption subkey
            << ExpiryChecker::Expired //
            << days{1};
    }

    void expiringEncryptionSubkey()
    {
        QFETCH(GpgME::Key, key);
        QFETCH(ExpiryChecker::CheckFlags, checkFlags);
        QFETCH(QDateTime, fakedate);
        QFETCH(ExpiryChecker::ExpirationStatus, expectedStatus);
        QFETCH(Kleo::chrono::days, expectedDuration);

        ExpiryChecker checker(ExpiryCheckerSettings{days{5}, days{5}, days{5}, days{5}});
        checker.setTimeProviderForTest(std::make_shared<FakeTimeProvider>(fakedate));
        const auto result = checker.checkKey(key, checkFlags);
        QCOMPARE(result.checkFlags, checkFlags);
        QCOMPARE(result.expiration.certificate, key);
        QCOMPARE(result.expiration.status, expectedStatus);
        if (expectedStatus != ExpiryChecker::NotNearExpiry) {
            // duration is undefined if status is NotNearExpiry
            QCOMPARE(result.expiration.duration, expectedDuration);
        }
    }

    void notExpiringEncryptionSubkey_data()
    {
        QTest::addColumn<GpgME::Key>("key");
        QTest::addColumn<ExpiryChecker::CheckFlags>("checkFlags");
        QTest::addColumn<QDateTime>("fakedate");
        QTest::addColumn<ExpiryChecker::ExpirationStatus>("expectedStatus");
        QTest::addColumn<Kleo::chrono::days>("expectedDuration");

        QTest::newRow("valid - sign") //
            << testKey("expires@example.net", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::OwnSigningKey} //
            << QDateTime{{2023, 4, 24}, {}, QTimeZone::UTC} // 9 days before expiration of primary key
            << ExpiryChecker::NotNearExpiry //
            << days{0}; // ignored
        QTest::newRow("valid - encrypt to self") //
            << testKey("expires@example.net", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::OwnEncryptionKey} //
            << QDateTime{{2023, 4, 24}, {}, QTimeZone::UTC} // 9 days before expiration of primary key
            << ExpiryChecker::NotNearExpiry //
            << days{0}; // ignored
        QTest::newRow("valid - encrypt to others") //
            << testKey("expires@example.net", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::EncryptionKey} //
            << QDateTime{{2023, 4, 24}, {}, QTimeZone::UTC} // 9 days before expiration of primary key
            << ExpiryChecker::NotNearExpiry //
            << days{0}; // ignored
        QTest::newRow("near expiry - sign") //
            << testKey("expires@example.net", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::OwnSigningKey} //
            << QDateTime{{2023, 5, 2}, {}, QTimeZone::UTC} // 1 day before expiration of primary key
            << ExpiryChecker::ExpiresSoon //
            << days{1};
        QTest::newRow("near expiry - encrypt to self") //
            << testKey("expires@example.net", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::OwnEncryptionKey} //
            << QDateTime{{2023, 5, 2}, {}, QTimeZone::UTC} // 1 day before expiration of primary key
            << ExpiryChecker::ExpiresSoon //
            << days{1};
        QTest::newRow("near expiry - encrypt to others") //
            << testKey("expires@example.net", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::EncryptionKey} //
            << QDateTime{{2023, 5, 2}, {}, QTimeZone::UTC} // 1 day before expiration of primary key
            << ExpiryChecker::ExpiresSoon //
            << days{1};
        QTest::newRow("expired - sign") //
            << testKey("expires@example.net", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::OwnSigningKey} //
            << QDateTime{{2023, 5, 4}, {}, QTimeZone::UTC} // 1 day after expiration of primary key
            << ExpiryChecker::Expired //
            << days{1};
        QTest::newRow("expired - encrypt to self") //
            << testKey("expires@example.net", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::OwnEncryptionKey} //
            << QDateTime{{2023, 5, 4}, {}, QTimeZone::UTC} // 1 day after expiration of primary key
            << ExpiryChecker::Expired //
            << days{1};
        QTest::newRow("expired - encrypt to others") //
            << testKey("expires@example.net", GpgME::OpenPGP) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::EncryptionKey} //
            << QDateTime{{2023, 5, 4}, {}, QTimeZone::UTC} // 1 day after expiration of primary key
            << ExpiryChecker::Expired //
            << days{1};
    }

    void notExpiringEncryptionSubkey()
    {
        QFETCH(GpgME::Key, key);
        QFETCH(ExpiryChecker::CheckFlags, checkFlags);
        QFETCH(QDateTime, fakedate);
        QFETCH(ExpiryChecker::ExpirationStatus, expectedStatus);
        QFETCH(Kleo::chrono::days, expectedDuration);

        ExpiryChecker checker(ExpiryCheckerSettings{days{5}, days{5}, days{5}, days{5}});
        checker.setTimeProviderForTest(std::make_shared<FakeTimeProvider>(fakedate));
        const auto result = checker.checkKey(key, checkFlags);
        QCOMPARE(result.checkFlags, checkFlags);
        QCOMPARE(result.expiration.certificate, key);
        QCOMPARE(result.expiration.status, expectedStatus);
        if (expectedStatus != ExpiryChecker::NotNearExpiry) {
            // duration is undefined if status is NotNearExpiry
            QCOMPARE(result.expiration.duration, expectedDuration);
        }
    }

    void certificateChain_data()
    {
        QTest::addColumn<GpgME::Key>("key");
        QTest::addColumn<ExpiryChecker::CheckFlags>("checkFlags");
        QTest::addColumn<QDateTime>("fakedate");
        QTest::addColumn<ExpiryChecker::ExpirationStatus>("expectedStatus");
        QTest::addColumn<Kleo::chrono::days>("expectedDuration");
        QTest::addColumn<int>("expectedChainResults");
        QTest::addColumn<GpgME::Key>("expectedChainCertificate");
        QTest::addColumn<ExpiryChecker::ExpirationStatus>("expectedChainStatus");
        QTest::addColumn<Kleo::chrono::days>("expectedChainDuration");
        QTest::addColumn<int>("emissions");
        QTest::addColumn<QByteArray>("keyID");
        QTest::addColumn<QString>("msg");

        QTest::newRow("certificate near expiry; issuer okay") //
            << testKey("3193786A48BDF2D4D20B8FC6501F4DE8BE231B05", GpgME::CMS) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::CertificationKey | ExpiryChecker::CheckChain} //
            << QDateTime{{2019, 6, 19}, {}, QTimeZone::UTC} // 5 days before expiration date of the certificate
            << ExpiryChecker::ExpiresSoon //
            << days{5} //
            << 0 // no expired or expiring certificates in issuer chain
            << Key{} // ignored
            << ExpiryChecker::ExpirationStatus{} // ignored
            << days{} // ignored
            << 1 // expect 1 signal emission because of a 2-certificate chain with 1 cert near expiry
            << QByteArray{"501F4DE8BE231B05"} // first signal emission references the certificate
            << QStringLiteral(
                   "<p>The S/MIME certificate for</p><p align=center><b>CN=AddTrust External CA Root,OU=AddTrust External TTP Network,O=AddTrust AB,C=SE</b> "
                   "(serial number 51260A931CE27F9CC3A55F79E072AE82)</p><p>expires in 5 days.</p>");
        QTest::newRow("certificate near expiry; issuer not checked") //
            << testKey("3193786A48BDF2D4D20B8FC6501F4DE8BE231B05", GpgME::CMS) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::CertificationKey} //
            << QDateTime{{2019, 6, 19}, {}, QTimeZone::UTC} // 5 days before expiration date of the certificate
            << ExpiryChecker::ExpiresSoon //
            << days{5} //
            << 0 // issuer chain not checked
            << Key{} // ignored
            << ExpiryChecker::ExpirationStatus{} // ignored
            << days{} // ignored
            << 1 // expect 1 signal emission because certificate is near expiry
            << QByteArray{"501F4DE8BE231B05"} // signal emission references the certificate
            << QStringLiteral(
                   "<p>The S/MIME certificate for</p><p align=center><b>CN=AddTrust External CA Root,OU=AddTrust External TTP Network,O=AddTrust AB,C=SE</b> "
                   "(serial number 51260A931CE27F9CC3A55F79E072AE82)</p><p>expires in 5 days.</p>");
        QTest::newRow("certificate okay; issuer near expiry") //
            << testKey("9E99817D12280C9677674430492EDA1DCE2E4C63", GpgME::CMS) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::CertificationKey | ExpiryChecker::CheckChain} //
            << QDateTime{{2019, 6, 19}, {}, QTimeZone::UTC} // 5 days before expiration date of the issuer certificate
            << ExpiryChecker::NotNearExpiry //
            << days{346} //
            << 1 // one expiring certificate in issuer chain
            << testKey("3193786A48BDF2D4D20B8FC6501F4DE8BE231B05", GpgME::CMS) //
            << ExpiryChecker::ExpiresSoon //
            << days{5} //
            << 1 // expect 1 signal emission because of a 2-certificate chain with 1 cert near expiry
            << QByteArray{"501F4DE8BE231B05"} // first signal emission references the isser certificate
            << QStringLiteral(
                   "<p>The intermediate CA certificate</p><p align=center><b>CN=AddTrust External CA Root,OU=AddTrust External TTP Network,O=AddTrust "
                   "AB,C=SE</b></p><p>for S/MIME certificate</p><p align=center><b>CN=UTN - DATACorp SGC,L=Salt Lake "
                   "City,SP=UT,OU=http://www.usertrust.com,O=The USERTRUST Network,C=US</b> (serial number 46EAF096054CC5E3FA65EA6E9F42C664)</p><p>expires in "
                   "5 days.</p>");
        QTest::newRow("certificate okay; issuer not checked") //
            << testKey("9E99817D12280C9677674430492EDA1DCE2E4C63", GpgME::CMS) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::CertificationKey} //
            << QDateTime{{2019, 6, 19}, {}, QTimeZone::UTC} // 5 days before expiration date of the issuer certificate
            << ExpiryChecker::NotNearExpiry //
            << days{346} //
            << 0 // issuer chain not checked
            << Key{} // ignored
            << ExpiryChecker::ExpirationStatus{} // ignored
            << days{} // ignored
            << 0 // expect 0 signal emission because certificate is not near expiry
            << QByteArray{} //
            << QString{};
        QTest::newRow("certificate near expiry; issuer expired") //
            << testKey("9E99817D12280C9677674430492EDA1DCE2E4C63", GpgME::CMS) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::CertificationKey | ExpiryChecker::CheckChain} //
            << QDateTime{{2020, 5, 25}, {}, QTimeZone::UTC} // 5 days before expiration date of the certificate
            << ExpiryChecker::ExpiresSoon //
            << days{5} //
            << 1 // one expired certificate in issuer chain
            << testKey("3193786A48BDF2D4D20B8FC6501F4DE8BE231B05", GpgME::CMS) //
            << ExpiryChecker::Expired //
            << days{336} //
            << 2 // expect 2 signal emissions because both certificates in the 2-certificate chain are either expired or near expiry
            << QByteArray{"492EDA1DCE2E4C63"} // first signal emission references the certificate
            << QStringLiteral(
                   "<p>The S/MIME certificate for</p><p align=center><b>CN=UTN - DATACorp SGC,L=Salt Lake City,SP=UT,OU=http://www.usertrust.com,O=The "
                   "USERTRUST Network,C=US</b> (serial number 46EAF096054CC5E3FA65EA6E9F42C664)</p><p>expires in 5 days.</p>");
        QTest::newRow("certificate near expiry; issuer not checked")
            << testKey("9E99817D12280C9677674430492EDA1DCE2E4C63", GpgME::CMS) //
            << ExpiryChecker::CheckFlags{ExpiryChecker::CertificationKey} //
            << QDateTime{{2020, 5, 25}, {}, QTimeZone::UTC} // 5 days before expiration date of the certificate
            << ExpiryChecker::ExpiresSoon //
            << days{5} //
            << 0 // issuer chain not checked
            << Key{} // ignored
            << ExpiryChecker::ExpirationStatus{} // ignored
            << days{} // ignored
            << 1 // expect 1 signal emission because certificate is near expiry
            << QByteArray{"492EDA1DCE2E4C63"} // first signal emission references the certificate
            << QStringLiteral(
                   "<p>The S/MIME certificate for</p><p align=center><b>CN=UTN - DATACorp SGC,L=Salt Lake City,SP=UT,OU=http://www.usertrust.com,O=The "
                   "USERTRUST Network,C=US</b> (serial number 46EAF096054CC5E3FA65EA6E9F42C664)</p><p>expires in 5 days.</p>");
    }

    void certificateChain()
    {
        QFETCH(GpgME::Key, key);
        QFETCH(ExpiryChecker::CheckFlags, checkFlags);
        QFETCH(QDateTime, fakedate);
        QFETCH(ExpiryChecker::ExpirationStatus, expectedStatus);
        QFETCH(Kleo::chrono::days, expectedDuration);
        QFETCH(int, expectedChainResults);
        QFETCH(GpgME::Key, expectedChainCertificate);
        QFETCH(ExpiryChecker::ExpirationStatus, expectedChainStatus);
        QFETCH(Kleo::chrono::days, expectedChainDuration);
        QFETCH(int, emissions);
        QFETCH(QByteArray, keyID);
        QFETCH(QString, msg);

        {
            ExpiryChecker checker(ExpiryCheckerSettings{days{1}, days{10}, days{10}, days{10}});
            checker.setTimeProviderForTest(std::make_shared<FakeTimeProvider>(fakedate));
            QSignalSpy spy(&checker, &ExpiryChecker::expiryMessage);
            const auto result = checker.checkKey(key, checkFlags);
            QCOMPARE(result.checkFlags, checkFlags);
            QCOMPARE(result.expiration.certificate, key);
            QCOMPARE(result.expiration.status, expectedStatus);
            QCOMPARE(result.expiration.duration, expectedDuration);
            QCOMPARE(result.chainExpiration.size(), expectedChainResults);
            if (result.chainExpiration.size() > 0) {
                const auto issuerExpiration = result.chainExpiration.front();
                QCOMPARE(issuerExpiration.status, expectedChainStatus);
                QCOMPARE(issuerExpiration.duration, expectedChainDuration);
            }
            QCOMPARE(spy.count(), emissions);
            if (emissions > 0) {
                QList<QVariant> arguments = spy.takeFirst();
                QCOMPARE(arguments.at(0).value<GpgME::Key>().keyID(), keyID);
                QCOMPARE(arguments.at(1).toString(), msg);
                QCOMPARE(arguments.at(2).value<ExpiryChecker::ExpiryInformation>(), ExpiryChecker::OtherKeyNearExpiry);
            }
        }
    }

    void noSuitableSubkey_data()
    {
        QTest::addColumn<GpgME::Key>("key");
        QTest::addColumn<ExpiryChecker::CheckFlags>("checkFlags");

        QTest::newRow("OpenPGP; no encryption subkey") //
            << testKey("sign-only@example.net", GpgME::OpenPGP) // sign-only key
            << ExpiryChecker::CheckFlags{ExpiryChecker::EncryptionKey};
        QTest::newRow("S/MIME; no encryption key") //
            << testKey("3193786A48BDF2D4D20B8FC6501F4DE8BE231B05", GpgME::CMS) // certification-only key
            << ExpiryChecker::CheckFlags{ExpiryChecker::EncryptionKey};
        QTest::newRow("S/MIME; no signing key") //
            << testKey("3193786A48BDF2D4D20B8FC6501F4DE8BE231B05", GpgME::CMS) // certification-only key
            << ExpiryChecker::CheckFlags{ExpiryChecker::SigningKey};
    }

    void noSuitableSubkey()
    {
        QFETCH(GpgME::Key, key);
        QFETCH(ExpiryChecker::CheckFlags, checkFlags);

        ExpiryChecker checker(ExpiryCheckerSettings{days{1}, days{1}, days{1}, days{1}});
        const auto result = checker.checkKey(key, checkFlags);
        QCOMPARE(result.expiration.certificate, key);
        QCOMPARE(result.expiration.status, ExpiryChecker::NoSuitableSubkey);
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
    // sub   cv25519 2019-01-22 [E] [expired: 2021-01-21]
    //
    // pub   ed25519 2023-04-17 [SC]
    //       C1218845DEEDA5432198FA7AF78A0834BB3C4A16
    // uid           [ultimate] encr-expires@example.net
    // sub   cv25519 2023-04-17 [E] [expires: 2023-04-27]
    //
    // pub   ed25519 2023-05-02 [SC] [expires: 2023-05-03]
    //       C3607CB03C13FDC6CB0384649358227B5DD4D260
    // uid           [ultimate] expires@example.net
    // sub   cv25519 2023-05-02 [E]
    //
    // pub   ed25519 2023-05-02 [SC] [expires: 2023-05-03]
    //       26C9EEEA094AC00FDA0FFC1384EFDDEEC99C022F
    // uid           [ultimate] sign-only@example.net
    //
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
    //
    // S/MIME certificates building a circular chain
    //
    //            ID: 0xBE231B05
    //           S/N: 51260A931CE27F9CC3A55F79E072AE82
    //         (dec): 107864989418777835411218143713715990146
    //        Issuer: /CN=UTN - DATACorp SGC/OU=http:\x2f\x2fwww.usertrust.com/O=The USERTRUST Network/L=Salt Lake City/ST=UT/C=US
    //       Subject: /CN=AddTrust External CA Root/OU=AddTrust External TTP Network/O=AddTrust AB/C=SE
    //      validity: 2005-06-07 08:09:10 through 2019-06-24 19:06:30
    //      key type: rsa2048
    //     key usage: certSign crlSign
    // ext key usage: ms-serverGatedCrypto (suggested), serverGatedCrypto.ns (suggested)
    //  chain length: unlimited
    //      sha1 fpr: 31:93:78:6A:48:BD:F2:D4:D2:0B:8F:C6:50:1F:4D:E8:BE:23:1B:05
    //      sha2 fpr: 92:5E:4B:37:2B:A3:2E:5E:87:30:22:84:B2:D7:C9:DF:BF:82:00:FF:CB:A0:D1:66:03:A1:A0:6F:F7:6C:D3:53
    //
    //            ID: 0xCE2E4C63
    //           S/N: 46EAF096054CC5E3FA65EA6E9F42C664
    //         (dec): 94265836834010752231943569188608722532
    //        Issuer: /CN=AddTrust External CA Root/OU=AddTrust External TTP Network/O=AddTrust AB/C=SE
    //       Subject: /CN=UTN - DATACorp SGC/OU=http:\x2f\x2fwww.usertrust.com/O=The USERTRUST Network/L=Salt Lake City/ST=UT/C=US
    //      validity: 2005-06-07 08:09:10 through 2020-05-30 10:48:38
    //      key type: rsa2048
    //     key usage: certSign crlSign
    // ext key usage: ms-serverGatedCrypto (suggested), serverGatedCrypto.ns (suggested)
    //      policies: 2.5.29.32.0:N:
    //  chain length: unlimited
    //      sha1 fpr: 9E:99:81:7D:12:28:0C:96:77:67:44:30:49:2E:DA:1D:CE:2E:4C:63
    //      sha2 fpr: 21:3F:AD:03:B1:C5:23:47:E9:A8:0F:29:9A:F0:89:9B:CA:FF:3F:62:B3:4E:B0:60:66:F4:D7:EE:A5:EE:1A:73

    Key testKey(const char *pattern, Protocol protocol = UnknownProtocol)
    {
        const std::vector<Key> keys = KeyCache::instance()->findByEMailAddress(pattern);
        for (const auto &key : keys) {
            if (protocol == UnknownProtocol || key.protocol() == protocol) {
                return key;
            }
        }
        const auto key = KeyCache::instance()->findByKeyIDOrFingerprint(pattern);
        if (key.isNull()) {
            qWarning() << "No" << Formatting::displayName(protocol) << "test key found for" << pattern;
        }
        return key;
    }

private:
    QSharedPointer<QTemporaryDir> mGnupgHome;
    std::shared_ptr<const KeyCache> mKeyCache;
};

QTEST_MAIN(ExpiryCheckerTest)
#include "expirycheckertest.moc"
