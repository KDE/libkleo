/*
    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <Libkleo/KeyCache>

#include <QGpgME/DataProvider>
#include <QGpgME/Protocol>
#include <QGpgME/VerifyOpaqueJob>

#include <QObject>
#include <QTest>

#include <gpgme++/data.h>
#include <gpgme++/engineinfo.h>
#include <gpgme++/key.h>

#include <gpgme.h>

#include <memory>

using namespace Kleo;
using namespace GpgME;

// Curve 448 test key with signing subkey (this key has V5 fingerprints)
// pub   ed448 2024-09-23 [SC]
//       1DE1960C29F97E6762C4EA341820DAAC045579921E0F30567354CCC69FD42A1D
// uid           [ultimate] Curve 448 <curve448@example.net>
// sub   cv448 2024-09-23 [E]
//       C4B4474450015DC3F84033F2C4A264D932E7801AA01EA6E53BCB685CCDEEB2A1
// sub   ed448 2024-09-24 [S]
//       C23ADF7C336FEBA6D06DAEE8A780B01CF612BF25FCF3AB915176D8126A1FAB3A
static const char *key_v5_curve_448_fpr = "1DE1960C29F97E6762C4EA341820DAAC045579921E0F30567354CCC69FD42A1D";
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

static const char *clearsigned_using_signing_subkey_of_curve_448 =
    "-----BEGIN PGP SIGNED MESSAGE-----\n"
    "Hash: SHA512\n"
    "\n"
    "This text has been signed using the signing subkey.\n"
    "-----BEGIN PGP SIGNATURE-----\n"
    "\n"
    "iL8FARYKAD8iIQXCOt98M2/rptBtruingLAc9hK/Jfzzq5FRdtgSah+rOgUCZvKA\n"
    "WRUcY3VydmU0NDhAZXhhbXBsZS5uZXQAAL/XAcdB4k/CCG0JSxr4tWkTDlCKLnSd\n"
    "8tyoxOJb3UiNOExJ1jflFw0llmHQ4xMV67RfHtM/CYgF/W0dewABx0vtH5AzqCbC\n"
    "w1Z3jt5L1gX6oLWHwTPvgoZhlwgSwFAX27yeAj9osHfma4hYkVr8dmU1Fp8T4hkq\n"
    "AA==\n"
    "=y6rF\n"
    "-----END PGP SIGNATURE-----\n";

namespace
{
}

class KeyCacheTest : public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void initTestCase()
    {
        GpgME::initializeLibrary();
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() >= "2.4.0") {
            QGpgME::QByteArrayDataProvider dp(key_v5_curve_448);
            Data data(&dp);
            const auto keys = data.toKeys();
            QCOMPARE(keys.size(), 1);
            const auto key = keys[0];
            QVERIFY(!key.isNull());
            QCOMPARE(std::string_view{key.primaryFingerprint()}, key_v5_curve_448_fpr);
            keyCurve448 = key;
        }
    }

    void test_findSigner_v5_primary_key()
    {
        const auto keyCache = KeyCache::instance();
        KeyCache::mutableInstance()->setKeys({keyCurve448});

        const QByteArray signedData{clearsigned_using_primary_key_of_curve_448};
        const std::unique_ptr<QGpgME::VerifyOpaqueJob> verifyJob{QGpgME::openpgp()->verifyOpaqueJob(true)};
        QByteArray verified;

        const VerificationResult result = verifyJob->exec(signedData, verified);
        QVERIFY(!result.error());

        QCOMPARE(result.numSignatures(), 1);
        const Key key = keyCache->findSigner(result.signature(0));
        QCOMPARE(std::string_view{key.primaryFingerprint()}, key_v5_curve_448_fpr);
    }

    void test_findSigners_v5_primary_key()
    {
        const auto keyCache = KeyCache::instance();
        KeyCache::mutableInstance()->setKeys({keyCurve448});

        const QByteArray signedData{clearsigned_using_primary_key_of_curve_448};
        const std::unique_ptr<QGpgME::VerifyOpaqueJob> verifyJob{QGpgME::openpgp()->verifyOpaqueJob(true)};
        QByteArray verified;

        const VerificationResult result = verifyJob->exec(signedData, verified);
        QVERIFY(!result.error());

        const auto keys = keyCache->findSigners(result);
        QCOMPARE(keys.size(), 1);
        QCOMPARE(std::string_view{keys.front().primaryFingerprint()}, key_v5_curve_448_fpr);
    }

    void test_findSigner_v5_subkey_key()
    {
        const auto keyCache = KeyCache::instance();
        KeyCache::mutableInstance()->setKeys({keyCurve448});

        const QByteArray signedData{clearsigned_using_signing_subkey_of_curve_448};
        const std::unique_ptr<QGpgME::VerifyOpaqueJob> verifyJob{QGpgME::openpgp()->verifyOpaqueJob(true)};
        QByteArray verified;

        const VerificationResult result = verifyJob->exec(signedData, verified);
        QVERIFY(!result.error());

        QCOMPARE(result.numSignatures(), 1);
        const Key key = keyCache->findSigner(result.signature(0));
        QCOMPARE(std::string_view{key.primaryFingerprint()}, key_v5_curve_448_fpr);
    }

    void test_findSigners_v5_subkey_key()
    {
        const auto keyCache = KeyCache::instance();
        KeyCache::mutableInstance()->setKeys({keyCurve448});

        const QByteArray signedData{clearsigned_using_signing_subkey_of_curve_448};
        const std::unique_ptr<QGpgME::VerifyOpaqueJob> verifyJob{QGpgME::openpgp()->verifyOpaqueJob(true)};
        QByteArray verified;

        const VerificationResult result = verifyJob->exec(signedData, verified);
        QVERIFY(!result.error());

        const auto keys = keyCache->findSigners(result);
        QCOMPARE(keys.size(), 1);
        QCOMPARE(std::string_view{keys.front().primaryFingerprint()}, key_v5_curve_448_fpr);
    }

private:
    GpgME::Key keyCurve448;
};

QTEST_MAIN(KeyCacheTest)
#include "keycachetest.moc"
