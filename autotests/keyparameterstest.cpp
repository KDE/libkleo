/* -*- mode: c++; c-basic-offset:4 -*-

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <Libkleo/KeyParameters>
#include <Libkleo/KeyUsage>

#include <QDate>
#include <QTest>

#include <gpgme++/key.h>

using namespace Kleo;

class KeyParametersTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void test_OpenPGP_key()
    {
        KeyParameters params{KeyParameters::OpenPGP};
        params.setName(QStringLiteral("Ada Lovelace"));
        params.setEmail(QStringLiteral("ada.lovelace@example.net"));
        params.setKeyType(GpgME::Subkey::AlgoEDDSA);
        params.setKeyCurve(QStringLiteral("ed25519"));
        params.setKeyUsage(KeyUsage{KeyUsage::Sign | KeyUsage::Authenticate});
        params.setSubkeyType(GpgME::Subkey::AlgoECDH);
        params.setSubkeyCurve(QStringLiteral("cv25519"));
        params.setSubkeyUsage(KeyUsage{KeyUsage::Encrypt});
        params.setExpirationDate(QDate{2024, 12, 10});

        QCOMPARE(params.toString(),
                 QStringLiteral("<GnupgKeyParms format=\"internal\">\n"
                                "%ask-passphrase\n"
                                "Key-Type:EdDSA\n"
                                "Key-Curve:ed25519\n"
                                "Key-Usage:sign auth\n"
                                "Subkey-Type:ECDH\n"
                                "Subkey-Usage:encrypt\n"
                                "Subkey-Curve:cv25519\n"
                                "Expire-Date:2024-12-10\n"
                                "Name-Real:Ada Lovelace\n"
                                "Name-Email:ada.lovelace@example.net\n"
                                "</GnupgKeyParms>"));
    }

    void test_SMIME_CSR()
    {
        KeyParameters params{KeyParameters::CMS};
        params.setDN(QStringLiteral("CN=Ada Lovelace,L=London,C=UK"));
        params.setEmail(QStringLiteral("ada.lovelace@example.net"));
        params.addEmail(QStringLiteral(u"ada@t\u00E4st.example.org"));
        params.setKeyType(GpgME::Subkey::AlgoRSA);
        params.setKeyLength(3072);
        params.setKeyUsage(KeyUsage{KeyUsage::Sign | KeyUsage::Encrypt});
        params.addDomainName(QStringLiteral("ada.example.net"));
        params.addDomainName(QStringLiteral(u"t\u00E4st.example.org"));
        params.addURI(QStringLiteral("https://ada.example.net"));
        params.addURI(QStringLiteral("https://lovelace.example.org"));
        QCOMPARE(params.toString(),
                 QStringLiteral("<GnupgKeyParms format=\"internal\">\n"
                                "Key-Type:RSA\n"
                                "Key-Length:3072\n"
                                "Key-Usage:sign encrypt\n"
                                "Name-DN:CN=Ada Lovelace,L=London,C=UK\n"
                                "Name-Email:ada.lovelace@example.net\n"
                                "Name-Email:ada@xn--tst-qla.example.org\n"
                                "Name-DNS:ada.example.net\n"
                                "Name-DNS:xn--tst-qla.example.org\n"
                                "Name-URI:https://ada.example.net\n"
                                "Name-URI:https://lovelace.example.org\n"
                                "</GnupgKeyParms>"));
    }

    void test_SMIME_CSR_for_card_key()
    {
        KeyParameters params{KeyParameters::CMS};
        params.setDN(QStringLiteral("CN=Ada Lovelace,L=London,C=UK"));
        params.setEmail(QStringLiteral("ada@example.net"));
        params.setCardKeyRef(QStringLiteral("OPENPGP.1"));
        params.setKeyUsage(KeyUsage{KeyUsage::Sign});
        QCOMPARE(params.toString(),
                 QStringLiteral("<GnupgKeyParms format=\"internal\">\n"
                                "Key-Type:card:OPENPGP.1\n"
                                "Key-Usage:sign\n"
                                "Name-DN:CN=Ada Lovelace,L=London,C=UK\n"
                                "Name-Email:ada@example.net\n"
                                "</GnupgKeyParms>"));
    }
};

QTEST_MAIN(KeyParametersTest)
#include "keyparameterstest.moc"
