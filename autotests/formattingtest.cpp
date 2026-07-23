/*
    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>

#include <QGpgME/Debug>
#include <QGpgME/ImportJob>
#include <QGpgME/Protocol>
#include <QGpgME/SignJob>
#include <QGpgME/VerifyDetachedJob>
#include <QGpgME/VerifyOpaqueJob>

#include <QProcess>
#include <QTest>

#include <gpgme++/engineinfo.h>
#include <gpgme++/importresult.h>
#include <gpgme++/signingresult.h>
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

static const char *opaque_smime_signed_data =
    "-----BEGIN SIGNED MESSAGE-----\n"
    "MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0B\n"
    "BwGggCSABAlTaWduIG1lIQoAAAAAAAAxggLmMIIC4gIBATB+MHgxCzAJBgNVBAYT\n"
    "AkRFMRYwFAYDVQQKEw1nMTAgQ29kZSBHbWJIMRAwDgYDVQQLEwdUZXN0bGFiMR4w\n"
    "HAYDVQQDExVnMTAgQ29kZSBURVNUIENBIDIwMTkxHzAdBgkqhkiG9w0BCQEWEGlu\n"
    "Zm9AZzEwY29kZS5jb20CAhoDMA0GCWCGSAFlAwQCAQUAoIG6MBgGCSqGSIb3DQEJ\n"
    "AzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MDcyMjEyMjMzMlowLwYJ\n"
    "KoZIhvcNAQkEMSIEIKmQZ0JOVOovrhBksV3YI2d7ilQAdZccUJYySVzZ0+tYME8G\n"
    "CSqGSIb3DQEJDzFCMEAwCwYJYIZIAWUDBAEuMAsGCWCGSAFlAwQBBjALBglghkgB\n"
    "ZQMEASowCwYJYIZIAWUDBAECMAoGCCqGSIb3DQMHMA0GCSqGSIb3DQEBAQUABIIB\n"
    "gJ0L7QAD5cOvgW+qETBWZIUwnyFRwUdQuNMC71X1SCRJdIzRPecr38Tt0i2dGXA2\n"
    "Y7b6SGy9gOmy+DfqQ7GKPAmDyVqA1+sMOMnsF8CCB3DWdYbOWI18WAoPV49XOdra\n"
    "vVTdXzKgz91WgXjiMUaG8Rrq7kP0F5Yw3LStUKZzO6yOof/YnJQWL9kYo/04m5Lj\n"
    "ZkdwGW1o+WmFUcDO1OIEkxNmHWa/6wDlROT4HqH3ptwhXE9rMj8hA53tc7FlyACQ\n"
    "pqe4U/GSTyoCUmPvdiiKc2SlM7JpiBtujUfIrIGyoPamsYodtQspdEeGzJaoSTwd\n"
    "H9OJAmCRYIUrkAyE9XKediKkN7I7goQ0bbEUPMLCBuYGlaLmi6mjsdkXgBYDCfdl\n"
    "Lp5y93zATlDCNfFtFnpaNsdCiGGRiLQKZOGEfsySa3DSMqXy+CUkv51VVkPf2i9D\n"
    "Qx6gF4XphsJU9W0S+vjSCAFQ6e6zdAKduVLaTRrw29s11uNGdFebcMMPxGlGsNOd\n"
    "jQAAAAAAAA==\n"
    "-----END SIGNED MESSAGE-----\n";

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

class CustomGnuPGHome
{
public:
    CustomGnuPGHome(const QString &path)
    {
        init(path);
    }

    CustomGnuPGHome()
    {
    }

    ~CustomGnuPGHome()
    {
        QProcess::execute(u"gpgconf"_s, {u"--kill"_s, u"all"_s});
    }

    void init(const QString &path)
    {
        mGnupgHomeEnvVar.set("GNUPGHOME", path.toUtf8());
    }

private:
    EnvironmentVariableOverride mGnupgHomeEnvVar;
};

class TemporaryGnuPGHome : public CustomGnuPGHome
{
public:
    TemporaryGnuPGHome()
    {
        init(mGnupgHome.path());
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

    QByteArray readTestData(const QString &fileName) const
    {
        const QString filePath = ":/testdata/formattingtest/"_L1 + fileName;
        QFile file{filePath};
        if (!file.open(QFile::ReadOnly)) {
            qWarning() << "Failed to open test data file:" << filePath;
            return {};
        }
        return file.readAll();
    }

    QString maskDateAndTime(QString text) const
    {
        static const QString datePattern = u"[0-9]{1,4}[-/][0-9]{1,2}[-/][0-9]{1,4}"_s;
        // we use \W (any non-word character) instead of \s for matching trailing AM/PM because \s doesn't match \u202F (Narrow No-Break Space)
        static const QString timePattern = u"[0-9]{1,2}:[0-9]{2}(?::[0-9]{2})?(?:\\W[AP]M)?"_s;
        static const QRegularExpression dateTimeRegExp{datePattern + u' ' + timePattern};
        static const QRegularExpression dateRegExp{datePattern};
        static const QRegularExpression timeRegExp{timePattern};
        return text.replace(dateTimeRegExp, u"DATETIME"_s).replace(dateRegExp, u"DATE"_s).replace(timeRegExp, u"TIME"_s);
    }

private Q_SLOTS:
    void initTestCase()
    {
        GpgME::initializeLibrary();
    }

    void test_maskDateAndTime()
    {
        QCOMPARE(maskDateAndTime(u"07/05/26 05:07"_s), u"DATETIME"_s);
        QCOMPARE(maskDateAndTime(u"7/5/26"_s), u"DATE"_s);
        QCOMPARE(maskDateAndTime(u"07/05/2026"_s), u"DATE"_s);
        QCOMPARE(maskDateAndTime(u"2026-05-07"_s), u"DATE"_s);
        QCOMPARE(maskDateAndTime(u"5:07"_s), u"TIME"_s);
        QCOMPARE(maskDateAndTime(u"05:07"_s), u"TIME"_s);
        QCOMPARE(maskDateAndTime(u"05:07:08"_s), u"TIME"_s);
        QCOMPARE(maskDateAndTime(u"05:07 AM"_s), u"TIME"_s);
        QCOMPARE(maskDateAndTime(u"05:07:08 PM"_s), u"TIME"_s);
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

        const QString result = Formatting::prettySignature(verificationResult.signature(0), u"sender@example.net"_s);
        QCOMPARE(maskDateAndTime(result),
                 u"Signature created on DATETIME with certificate: "
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

        const QString result = Formatting::prettySignature(verificationResult.signature(0), u"sender@example.net"_s);
        QCOMPARE(maskDateAndTime(result),
                 u"Signature created on DATETIME using an unknown certificate with fingerprint <br/>"
                 "<a href='certificate:1DE1960C29F97E6762C4EA341820DAAC045579921E0F30567354CCC69FD42A1D'>1DE19 60C29 F97E6 762C4 EA341 820DA AC045 57992 1E0F3 "
                 "05673</a><br/>"
                 "You can search the certificate on a keyserver or import it from a file."_s);
    }

    void test_prettySignature_multiple_uids()
    {
        const auto temporaryDir = QTest::qExtractTestData(QStringLiteral("/fixtures/formattingtest"));
        const auto gnupgHome = CustomGnuPGHome(temporaryDir->path());
        const auto keyCache = KeyCache::instance();
        QVERIFY(!keyCache->keys().empty());

        const auto firstUID = u"uid_a@example.net"_s;
        const auto secondUID = u"uid_b@example.net"_s;
        const auto bogusUID = u"bogusuid@example.net"_s;
        const auto keys = keyCache->findByEMailAddress(firstUID.toLatin1().constData());
        QVERIFY(keys.size() == 1);
        const auto key = keys.at(0);
        QVERIFY(keyCache->findByEMailAddress(secondUID.toLatin1().constData()).size() == 1);
        QVERIFY(keyCache->findByEMailAddress(bogusUID.toLatin1().constData()).size() == 0);

        const auto signedData = "signed data"_ba;
        QByteArray signature;
        auto signJob{QGpgME::openpgp()->signJob(true, true)};
        auto signResult = signJob->exec({key}, signedData, GpgME::Detached, signature);
        QVERIFY(!signResult.error());

        auto verifyJob{QGpgME::openpgp()->verifyDetachedJob(true)};
        const VerificationResult verificationResult = verifyJob->exec(signature, signedData);
        QVERIFY(!verificationResult.error());
        QCOMPARE(verificationResult.numSignatures(), 1);

        const auto formatPrimaryUID = Formatting::prettySignature(verificationResult.signature(0), firstUID);
        QVERIFY(formatPrimaryUID.contains(firstUID));
        const auto formatSecondaryUID = Formatting::prettySignature(verificationResult.signature(0), secondUID);
        QVERIFY(formatSecondaryUID.contains(secondUID));
        const auto formatBogusUID = Formatting::prettySignature(verificationResult.signature(0), bogusUID);
        QVERIFY(!formatBogusUID.contains(bogusUID));
        QVERIFY(formatBogusUID.contains(secondUID));
        const auto formatAnyUID = Formatting::prettySignature(verificationResult.signature(0), QString());
        QVERIFY(formatAnyUID.contains(secondUID));
    }

    void test_prettyDataSignature_data()
    {
        QTest::addColumn<Signature::Summary>("sigSummary");
        QTest::addColumn<gpg_err_code_t>("sigStatus");
        QTest::addColumn<Signature::Validity>("sigValidity");
        QTest::addColumn<QString>("expected");

        QTest::newRow("all-good")
            << static_cast<Signature::Summary>(Signature::Summary::Green | Signature::Summary::Valid) << GPG_ERR_NO_ERROR << Signature::Validity::Full //
            << u"Signature verification was successful: Data and signature match and the certificate is valid and trusted.<br/>"
               "Signed by <a href=\"key:27E12CEFBE2E11FAF985106BD24D35D21E3C740D\">Certified Key &lt;certified@example.net&gt; (DATE)</a> on DATETIME."_s;
        QTest::newRow("key-expired")
            << Signature::Summary::KeyExpired << GPG_ERR_KEY_EXPIRED << Signature::Validity::Unknown
            << u"The data cannot be trusted. Reason: The signing certificate has expired.<br/>"
               "Signed by <a href=\"key:972263BC1577E48958A2AF7A6CFC883EEE0918B1\">Expired Key &lt;expired@example.net&gt; (DATE)</a> on DATETIME."_s;
        QTest::newRow("key-not-certified")
            << Signature::Summary::None << GPG_ERR_NO_ERROR << Signature::Validity::Unknown
            << u"The data cannot be trusted. Reason: It cannot be verified whether the data originates from the stated source.<br/>"
               "Signed by <a href=\"key:9152100939FC36332EC5954AD7ADC02ACDFA945A\">Not Certified &lt;not-certified@example.net&gt; (DATE)</a> on DATETIME."_s;
        QTest::newRow("key-revoked")
            << Signature::Summary::KeyRevoked << GPG_ERR_CERT_REVOKED << Signature::Validity::Unknown
            << u"The data cannot be trusted. Reason: The signing certificate has been revoked.<br/>"
               "Signed by <a href=\"key:BA80E58FB5EC794D6396D47ADABA14732513A6D6\">Revoked Key &lt;revoked@example.net&gt; (DATE)</a> on DATETIME."_s;
        QTest::newRow("key-unknown")
            << Signature::Summary::KeyMissing << GPG_ERR_NO_PUBKEY << Signature::Validity::Unknown
            << u"The signature cannot be verified because the corresponding certificate is not available. The data cannot be trusted. The signing "
               "certificate’s fingerprint is <a href=\"certificate:C8C6053CA0018BCB1C0D3C1AF9F33E35E1C16A17\">"
               "C8C6 053C A001 8BCB 1C0D  3C1A F9F3 3E35 E1C1 6A17</a>."_s;
        QTest::newRow("signature-bad")
            << Signature::Summary::Red << GPG_ERR_BAD_SIGNATURE << Signature::Validity::Unknown
            << u"The data cannot be trusted. Reason: Data and signature do not match.<br/>"
               "The signature claims to be from <a href=\"key:117C22E18017CB18A67FC3D699954415471E4A5F\">Second UID &lt;uid_b@example.net&gt; (DATE)</a>."_s;
        QTest::newRow("signature-expired")
            << Signature::Summary::SigExpired << GPG_ERR_SIG_EXPIRED << Signature::Validity::Unknown
            << u"The data cannot be trusted. Reason: The signature has expired.<br/>"
               "Signed by <a href=\"key:9152100939FC36332EC5954AD7ADC02ACDFA945A\">Not Certified &lt;not-certified@example.net&gt; (DATE)</a> on DATETIME."_s;
    }

    void test_prettyDataSignature()
    {
        QFETCH(Signature::Summary, sigSummary);
        QFETCH(gpg_err_code_t, sigStatus);
        QFETCH(Signature::Validity, sigValidity);
        QFETCH(QString, expected);
        const auto currentDataTag = QString::fromLatin1(QTest::currentDataTag());

        const auto temporaryDir = QTest::qExtractTestData(QStringLiteral("/fixtures/formattingtest"));
        const auto gnupgHome = CustomGnuPGHome(temporaryDir->path());

        const auto keyCache = KeyCache::instance();
        QVERIFY(!keyCache->keys().empty());

        const QString signedDataFile = "openpgp-signature-"_L1 + currentDataTag + ".txt"_L1;
        const QByteArray signature = readTestData(signedDataFile + ".sig"_L1);
        const QByteArray signedData = readTestData(signedDataFile);
        const std::unique_ptr<QGpgME::VerifyDetachedJob> verifyJob{QGpgME::openpgp()->verifyDetachedJob()};
        QByteArray verified;

        const VerificationResult verificationResult = verifyJob->exec(signature, signedData);
        // qWarning() << QGpgME::toLogString(verificationResult);
        QVERIFY(!verificationResult.error());
        QCOMPARE(verificationResult.numSignatures(), 1);
        const GpgME::Signature sig = verificationResult.signature(0);
        QCOMPARE(sig.summary(), sigSummary);
        QCOMPARE(sig.status().code(), sigStatus);
        QCOMPARE(sig.validity(), sigValidity);

        const QString result = Formatting::prettyDataSignature(verificationResult.signature(0), {});
        QCOMPARE(maskDateAndTime(result), expected);
    }

    void test_prettyDataSignature_unknown_smime_key()
    {
        const TemporaryGnuPGHome gnupgHome;

        const auto keyCache = KeyCache::instance();
        QVERIFY(keyCache->keys().empty());

        const QByteArray signedData{opaque_smime_signed_data};
        const std::unique_ptr<QGpgME::VerifyOpaqueJob> verifyJob{QGpgME::smime()->verifyOpaqueJob()};
        QByteArray verified;

        const VerificationResult verificationResult = verifyJob->exec(signedData, verified);
        QVERIFY(!verificationResult.error());
        QCOMPARE(verificationResult.numSignatures(), 1);

        const QString result = Formatting::prettyDataSignature(verificationResult.signature(0), {});
        const auto expected = u"The signature cannot be verified because the corresponding certificate is not available. The data cannot be trusted."_s;
        QCOMPARE(result, expected);
    }
};

QTEST_MAIN(FormattingTest)
#include "formattingtest.moc"
