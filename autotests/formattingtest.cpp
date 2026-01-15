/*
    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>

#include <QGpgME/ImportJob>
#include <QGpgME/Protocol>
#include <QGpgME/VerifyOpaqueJob>

#include <QProcess>
#include <QTest>

#include <gpgme++/engineinfo.h>
#include <gpgme++/importresult.h>
#include <gpgme++/verificationresult.h>

using namespace Kleo;
using namespace GpgME;
using namespace Qt::Literals::StringLiterals;

// Curve 448 test key with signing subkey (this key has V5 fingerprints)
// pub   ed448 2024-09-23 [SC]
//       1DE1960C29F97E6762C4EA341820DAAC045579921E0F30567354CCC69FD42A1D
// uid           [ultimate] Curve 448 <curve448@example.net>
// sub   cv448 2024-09-23 [E]
//       C4B4474450015DC3F84033F2C4A264D932E7801AA01EA6E53BCB685CCDEEB2A1
// sub   ed448 2024-09-24 [S]
//       C23ADF7C336FEBA6D06DAEE8A780B01CF612BF25FCF3AB915176D8126A1FAB3A
static const char *key_v5_curve_448 =
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
    "\n"
    "mEkFZvEwVRYAAAA/AytlcQHIoT/rN3uMR1yq3AFmBD10AENmlXqo6kaxcKY3v+MA\n"
    "MichexAlr27nYpImExbajnG9ic0AA65lWBwAtCBDdXJ2ZSA0NDggPGN1cnZlNDQ4\n"
    "QGV4YW1wbGUubmV0PojHBRMWCgBHAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4H\n"
    "AheAIiEFHeGWDCn5fmdixOo0GCDarARVeZIeDzBWc1TMxp/UKh0FAmbydZ0AAC51\n"
    "AcYvTOmPobit8ghAeooYqi9hqi/IAstruigFwqymFMfRVWz26Vkcf1cj5WrxhriC\n"
    "izPS0xW7o2C/IIABxjcfyaFADIuezHU7iOAHHlPcaidGtsAfjSZrXCJ852R1pgfz\n"
    "XdQHe5/lYk3KjifWVRtPF4PHu2ooALhMBWbxMFUSAAAAQgMrZW8Bv1H9Uzypq2rW\n"
    "EwRWr53dPsJkNUKlmjcJAMyegd07wEIf6ue6LZN4Ofb/g9xV5Frn6jHv5f5M2ayU\n"
    "AwEKCYisBRgWCgAsAhsMIiEFHeGWDCn5fmdixOo0GCDarARVeZIeDzBWc1TMxp/U\n"
    "Kh0FAmbyeR8AAANtAcjVaVJk1+B0n248Y+mXDr3x73FaD28MIt79oo8EPmoBr8An\n"
    "9sHP1alwPZ69RATb0ZRwbFHsuP2EMwAByPWsLPXCE0kkb0cNa9lbxgo/bkTrFwJC\n"
    "xVgEYZ1A9pP+6DjxyMoZACMqjvxWiXOz/z+zQUOm1+AmALhJBWbydVoWAAAAPwMr\n"
    "ZXEByIqrjBh9cBnQ9tvVvG5mEanDzkR6at4vHxJAsVNfPzjazoycfkBqZpBf5e2Z\n"
    "6iUm00eAvz4pjT1QAIkBVwUYFgoALCIhBR3hlgwp+X5nYsTqNBgg2qwEVXmSHg8w\n"
    "VnNUzMaf1CodBQJm8nVaAhsCAKuqIAUZFgoAKSIhBcI633wzb+um0G2u6KeAsBz2\n"
    "Er8l/POrkVF22BJqH6s6BQJm8nVaAADHFQHIttISB5goEUrK9MkOiDbPi9hxsNVw\n"
    "hFBSG29a++UYVpjZDHEWIJaXJDvcViFuA4Hli71mqSCh5d4AAcjzD3YNdVIH8z62\n"
    "BGHf8Ht1P4ZtwtkRYien9BUoeF/joQYFSm0wv+wERODqLsAmICAKhmsXosM5JQBG\n"
    "+wHGIdi7o+qpneBZSkifC9QqZdqEUDb7b9zPeOw2bHMMyD8NKfMwfjtGTBQxbrAL\n"
    "gbMrt0OYPzO1oW0AAcdfRLL6dBbRnrdMV765F+Qj8mUYAVTX4DFTjorjw7m3Y8cB\n"
    "pswH3njOP4PjbWi5JFuGiCzK0l9kDwA=\n"
    "=6h7G\n"
    "-----END PGP PUBLIC KEY BLOCK-----\n";

static const char *clearsigned_using_primary_key_of_curve_448 =
    "-----BEGIN PGP SIGNED MESSAGE-----\n"
    "Hash: SHA512\n"
    "\n"
    "This text has been signed using the primary key.\n"
    "-----BEGIN PGP SIGNATURE-----\n"
    "\n"
    "iKkFARYKACkiIQUd4ZYMKfl+Z2LE6jQYINqsBFV5kh4PMFZzVMzGn9QqHQUCZvKA\n"
    "NwAA5pIBxR9Hfqr1B4vCftVCOXvxrLN4UQsGRvn8hNbzYDfZFWBMhR8c20DiLidd\n"
    "jZXdz+qwKcYBcYMZbGldgAHIALoDksnjv60btHxjDmr0EtWRwofb9odo4r5lSb20\n"
    "zjZxbCyCmyhw8GLUr5KRY7crr6OPhyaJcAYA\n"
    "=1i3o\n"
    "-----END PGP SIGNATURE-----\n";

namespace
{

class EnvironmentVariableOverride
{
public:
    EnvironmentVariableOverride()
    {
    }

    EnvironmentVariableOverride(const char *varName, QByteArrayView value)
    {
        set(varName, value);
    }

    ~EnvironmentVariableOverride()
    {
        reset();
    }

    void set(const char *varName, QByteArrayView value)
    {
        if (mVarName.isEmpty()) {
            reset();
        }
        mWasSet = qEnvironmentVariableIsSet(varName);
        if (mWasSet) {
            mOldValue = qEnvironmentVariable(varName);
        }
        mVarName = varName;
        qputenv(mVarName.constData(), value);
    }

    void reset()
    {
        if (mVarName.isEmpty()) {
            return;
        }
        if (mWasSet) {
            qputenv(mVarName.constData(), mOldValue.toUtf8());
        } else {
            qunsetenv(mVarName.constData());
        }
        mVarName.clear();
    }

private:
    QByteArray mVarName;
    bool mWasSet;
    QString mOldValue;
};

class TemporaryGnuPGHome
{
public:
    TemporaryGnuPGHome()
    {
        mGnupgHomeEnvVar.set("GNUPGHOME", mGnupgHome.path().toUtf8());
    }

    ~TemporaryGnuPGHome()
    {
        QProcess::execute(u"gpgconf"_s, {u"--kill"_s, u"all"_s});
    }

    bool isValid() const
    {
        return mGnupgHome.isValid();
    }

    QString path() const
    {
        return mGnupgHome.path();
    }

private:
    EnvironmentVariableOverride mGnupgHomeEnvVar;
    QTemporaryDir mGnupgHome;
};

}

class FormattingTest : public QObject
{
    Q_OBJECT

public:
    static void initMain()
    {
        // force fixed locale and timezone for predictable text representation of QDateTime
        qputenv("LANG", "en_US");
        qputenv("TZ", "UTC");
    }

private Q_SLOTS:
    void initTestCase()
    {
        GpgME::initializeLibrary();
    }

    void test_prettyID_data()
    {
        QTest::addColumn<QByteArray>("id");
        QTest::addColumn<QString>("expected");

        QTest::newRow("empty string") //
            << ""_ba //
            << u""_s;
        QTest::newRow("short key ID") //
            << "01234567"_ba //
            << u"0123 4567"_s;
        QTest::newRow("key ID") //
            << "0123456789abcdef"_ba //
            << u"0123 4567 89AB CDEF"_s;
        QTest::newRow("V4 fingerprint") //
            << "0000111122223333444455556666777788889999"_ba //
            << u"0000 1111 2222 3333 4444  5555 6666 7777 8888 9999"_s;
        QTest::newRow("V5 fingerprint") //
            << "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"_ba //
            << u"00001 11122 22333 34444 55556 66677 77888 89999 AAAAB BBBCC"_s;
        QTest::newRow("string with length != 4*n") //
            << "0123456789abcd"_ba //
            << u"0123 4567 89AB CD"_s;
    }

    void test_prettyID()
    {
        QFETCH(QByteArray, id);
        QFETCH(QString, expected);

        QCOMPARE(Formatting::prettyID(id.constData()), expected);
    }

    void test_accessibleHexID_data()
    {
        QTest::addColumn<QByteArray>("id");
        QTest::addColumn<QString>("expected");

        QTest::newRow("empty string") //
            << ""_ba //
            << u""_s;
        QTest::newRow("short key ID") //
            << "01234567"_ba //
            << u"0 1 2 3, 4 5 6 7"_s;
        QTest::newRow("key ID") //
            << "0123456789abcdef"_ba //
            << u"0 1 2 3, 4 5 6 7, 8 9 a b, c d e f"_s;
        QTest::newRow("V4 fingerprint") //
            << "0000111122223333444455556666777788889999"_ba //
            << u"0 0 0 0, 1 1 1 1, 2 2 2 2, 3 3 3 3, 4 4 4 4, 5 5 5 5, 6 6 6 6, 7 7 7 7, 8 8 8 8, 9 9 9 9"_s;
        QTest::newRow("V5 fingerprint") //
            << "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"_ba //
            << u"0 0 0 0 1, 1 1 1 2 2, 2 2 3 3 3, 3 4 4 4 4, 5 5 5 5 6, 6 6 6 7 7, 7 7 8 8 8, 8 9 9 9 9, a a a a b, b b b c c"_s;
        QTest::newRow("string with length != 4*n") //
            << "0123456789abcd"_ba //
            << u"0123456789abcd"_s;
    }

    void test_accessibleHexID()
    {
        QFETCH(QByteArray, id);
        QFETCH(QString, expected);

        QCOMPARE(Formatting::accessibleHexID(id.constData()), expected);
    }

    void test_prettySignature_known_key()
    {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.4.0") {
            QSKIP("needs gpg 2.4.0+");
        }
        const TemporaryGnuPGHome gnupgHome;
        std::unique_ptr<QGpgME::ImportJob> importJob{QGpgME::openpgp()->importJob()};
        const ImportResult importResult = importJob->exec(key_v5_curve_448);
        QVERIFY(!importResult.error());
        QCOMPARE(importResult.numImported(), 1);

        const auto keyCache = KeyCache::instance();
        QVERIFY(!keyCache->keys().empty());

        const QByteArray signedData{clearsigned_using_primary_key_of_curve_448};
        const std::unique_ptr<QGpgME::VerifyOpaqueJob> verifyJob{QGpgME::openpgp()->verifyOpaqueJob(true)};
        QByteArray verified;

        const VerificationResult verificationResult = verifyJob->exec(signedData, verified);
        QVERIFY(!verificationResult.error());
        QCOMPARE(verificationResult.numSignatures(), 1);

        const QString resultWithoutTimestamp = Formatting::prettySignature(verificationResult.signature(0), u"sender@example.net"_s)
                                                   .replace(QRegularExpression{u"on .* with"_s}, u"on TIMESTAMP with"_s);
        QCOMPARE(resultWithoutTimestamp,
                 u"Signature created on TIMESTAMP with certificate: "
                 "<a href=\"key:1DE1960C29F97E6762C4EA341820DAAC045579921E0F30567354CCC69FD42A1D\">"
                 "Curve 448 &lt;curve448@example.net&gt; (1DE1 960C 29F9 7E67)"
                 "</a><br/>"
                 "The signature is valid but the used key is not certified by you or any trusted person.<br>"
                 "<strong>Warning:</strong> There is no indication that the signature belongs to the owner."_s);
    }

    void test_prettySignature_unknown_key()
    {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.4.0") {
            QSKIP("needs gpg 2.4.0+");
        }
        const TemporaryGnuPGHome gnupgHome;

        const auto keyCache = KeyCache::instance();
        QVERIFY(keyCache->keys().empty());

        const QByteArray signedData{clearsigned_using_primary_key_of_curve_448};
        const std::unique_ptr<QGpgME::VerifyOpaqueJob> verifyJob{QGpgME::openpgp()->verifyOpaqueJob(true)};
        QByteArray verified;

        const VerificationResult verificationResult = verifyJob->exec(signedData, verified);
        QVERIFY(!verificationResult.error());
        QCOMPARE(verificationResult.numSignatures(), 1);

        const QString resultWithoutTimestamp = Formatting::prettySignature(verificationResult.signature(0), u"sender@example.net"_s)
                                                   .replace(QRegularExpression{u"on .* using"_s}, u"on TIMESTAMP using"_s);
        QCOMPARE(resultWithoutTimestamp,
                 u"Signature created on TIMESTAMP using an unknown certificate with fingerprint <br/>"
                 "<a href='certificate:1DE1960C29F97E6762C4EA341820DAAC045579921E0F30567354CCC69FD42A1D'>1DE19 60C29 F97E6 762C4 EA341 820DA AC045 57992 1E0F3 "
                 "05673</a><br/>"
                 "You can search the certificate on a keyserver or import it from a file."_s);
    }
};

QTEST_MAIN(FormattingTest)
#include "formattingtest.moc"
