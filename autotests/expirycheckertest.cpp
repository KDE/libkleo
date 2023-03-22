/*
    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2022 Sandro Knauß <knauss@kde.org>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include "../src/kleo/expirychecker_p.h"

#include <Libkleo/ExpiryChecker>

#include <QGpgME/KeyListJob>
#include <QGpgME/Protocol>

#include <QDebug>
#include <QProcess>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>

#include <gpgme++/keylistresult.h>

using namespace Kleo;

static std::vector<GpgME::Key, std::allocator<GpgME::Key>> getKeys(bool smime = false)
{
    QGpgME::KeyListJob *job = nullptr;

    if (smime) {
        const QGpgME::Protocol *const backend = QGpgME::smime();
        Q_ASSERT(backend);
        job = backend->keyListJob(false);
    } else {
        const QGpgME::Protocol *const backend = QGpgME::openpgp();
        Q_ASSERT(backend);
        job = backend->keyListJob(false);
    }
    Q_ASSERT(job);

    std::vector<GpgME::Key> keys;
    GpgME::KeyListResult res = job->exec(QStringList(), true, keys);

    Q_ASSERT(!res.error());

    /*
    qDebug() << "got private keys:" << keys.size();

    for (std::vector< GpgME::Key >::iterator i = keys.begin(); i != keys.end(); ++i) {
        qDebug() << "key isnull:" << i->isNull() << "isexpired:" << i->isExpired();
        qDebug() << "key numuserIds:" << i->numUserIDs();
        for (uint k = 0; k < i->numUserIDs(); ++k) {
            qDebug() << "userIDs:" << i->userID(k).email();
        }
    }
    */

    return keys;
}

class ExpiryCheckerTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase()
    {
        qRegisterMetaType<ExpiryChecker::ExpiryInformation>();

        mGnupgHome = QTest::qExtractTestData(QStringLiteral("/fixtures/expirycheckertest"));
        qputenv("GNUPGHOME", mGnupgHome->path().toLocal8Bit());
    }

    void cleanupTestCase()
    {
        (void)QProcess::execute(QStringLiteral("gpgconf"), {"--kill", "all"});

        mGnupgHome.reset();
        qunsetenv("GNUPGHOME");
    }

    void valid_data()
    {
        QTest::addColumn<GpgME::Key>("key");
        QTest::addColumn<int>("difftime");
        QTest::newRow("neverExpire") << getKeys()[0] << -1;

        const auto backend = QGpgME::openpgp();
        Q_ASSERT(backend);
        const auto job = backend->keyListJob(false);
        Q_ASSERT(job);

        std::vector<GpgME::Key> keys;
        job->exec(QStringList() << QStringLiteral("EB85BB5FA33A75E15E944E63F231550C4F47E38E"), false, keys);
        QTest::newRow("openpgp") << keys[0] << 2 * 24 * 60 * 60;
        QTest::newRow("smime") << getKeys(true)[0] << 2 * 24 * 60 * 60;
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

        const auto backend = QGpgME::openpgp();
        Q_ASSERT(backend);
        const auto job = backend->keyListJob(false);
        Q_ASSERT(job);

        std::vector<GpgME::Key> keys;
        job->exec(QStringList() << QStringLiteral("EB85BB5FA33A75E15E944E63F231550C4F47E38E"), false, keys);
        QTest::newRow("openpgp")
            << keys[0]
            << QStringLiteral(
                   "<p>The OpenPGP key for</p><p align=center><b>alice@autocrypt.example</b> (KeyID 0xF231550C4F47E38E)</p><p>expired less than a day ago.</p>")
            << QStringLiteral(
                   "<p>Your OpenPGP encryption key</p><p align=center><b>alice@autocrypt.example</b> (KeyID 0xF231550C4F47E38E)</p><p>expired less than a day "
                   "ago.</p>")
            << QStringLiteral(
                   "<p>Your OpenPGP signing key</p><p align=center><b>alice@autocrypt.example</b> (KeyID 0xF231550C4F47E38E)</p><p>expired less than a day "
                   "ago.</p>");
        QTest::newRow("smime") << getKeys(true)[0]
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

        const auto backend = QGpgME::openpgp();
        Q_ASSERT(backend);
        const auto job = backend->keyListJob(false);
        Q_ASSERT(job);

        std::vector<GpgME::Key> keys;
        job->exec(QStringList() << QStringLiteral("EB85BB5FA33A75E15E944E63F231550C4F47E38E"), false, keys);
        QTest::newRow("openpgp")
            << keys[0]
            << QStringLiteral(
                   "<p>The OpenPGP key for</p><p align=center><b>alice@autocrypt.example</b> (KeyID 0xF231550C4F47E38E)</p><p>expires in less than 6 days.</p>")
            << QStringLiteral(
                   "<p>Your OpenPGP encryption key</p><p align=center><b>alice@autocrypt.example</b> (KeyID 0xF231550C4F47E38E)</p><p>expires in less than 6 "
                   "days.</p>")
            << QStringLiteral(
                   "<p>Your OpenPGP signing key</p><p align=center><b>alice@autocrypt.example</b> (KeyID 0xF231550C4F47E38E)</p><p>expires in less than 6 "
                   "days.</p>");
        QTest::newRow("smime") << getKeys(true)[0]
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
    QSharedPointer<QTemporaryDir> mGnupgHome;
};

QTEST_MAIN(ExpiryCheckerTest)
#include "expirycheckertest.moc"
