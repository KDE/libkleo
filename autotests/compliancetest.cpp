/*
    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include <Libkleo/Compliance>
#include <Libkleo/GnuPG>
#include <Libkleo/Test>

#include <QTest>

#include <gpgme++/key.h>

using namespace Kleo;
using namespace Qt::Literals::StringLiterals;

class ComplianceTest : public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void initTestCase()
    {
#if !LIBKLEO_FEATURE_DEVS_COMPLIANCE
        QSKIP("Test requires the de-vs compliance feature.");
#endif
    }

    void test_no_compliance_active()
    {
        Tests::FakeCryptoConfigStringValue fakeCompliance{"gpg", "compliance", QStringLiteral("")};
        // the "compliance_de_vs" config value shouldn't be used by any of the functions
        // Tests::FakeCryptoConfigIntValue fakeDeVsCompliance{"gpg", "compliance_de_vs", 0};
        QVERIFY(!DeVSCompliance::isActive());
        QVERIFY(!DeVSCompliance::isCompliant());
        QVERIFY(!DeVSCompliance::isBetaCompliance());

        // if compliance mode "de-vs" is not active then the following checks always return true
        QVERIFY(DeVSCompliance::algorithmIsCompliant("rsa2048"));
        QVERIFY(DeVSCompliance::allSubkeysAreCompliant(GpgME::Key{}));
        QVERIFY(DeVSCompliance::userIDIsCompliant(GpgME::UserID{}));
        QVERIFY(DeVSCompliance::keyIsCompliant(GpgME::Key{}));

        // all available algorithms are considered compliant
        QCOMPARE(DeVSCompliance::compliantAlgorithms(GpgME::OpenPGP), Kleo::availableAlgorithms(GpgME::OpenPGP));
        QCOMPARE(DeVSCompliance::compliantAlgorithms(GpgME::CMS), Kleo::availableAlgorithms(GpgME::CMS));

        QCOMPARE(DeVSCompliance::name(), QString{});
        QCOMPARE(DeVSCompliance::name(true), QString{});
        QCOMPARE(DeVSCompliance::name(false), QString{});
    }

    void test_de_vs_compliance_active_but_not_compliant()
    {
        Tests::FakeCryptoConfigStringValue fakeCompliance{"gpg", "compliance", QStringLiteral("de-vs")};
        Tests::FakeCryptoConfigIntValue fakeDeVsCompliance{"gpg", "compliance_de_vs", 0};
        QVERIFY(DeVSCompliance::isActive());
        QVERIFY(!DeVSCompliance::isCompliant());
        QVERIFY(!DeVSCompliance::isBetaCompliance());

        QVERIFY(!DeVSCompliance::algorithmIsCompliant("rsa2048"));
        QVERIFY(DeVSCompliance::algorithmIsCompliant("rsa3072"));

        QVERIFY(DeVSCompliance::compliantAlgorithms(GpgME::OpenPGP) != Kleo::availableAlgorithms(GpgME::OpenPGP));
        QVERIFY(DeVSCompliance::compliantAlgorithms(GpgME::CMS) != Kleo::availableAlgorithms(GpgME::CMS));

        QCOMPARE(DeVSCompliance::name(), u"Not VS-NfD compliant"_s);
        QCOMPARE(DeVSCompliance::name(true), u"VS-NfD compliant"_s);
        QCOMPARE(DeVSCompliance::name(false), u"Not VS-NfD compliant"_s);
    }

    void test_de_vs_compliance_active_and_compliant()
    {
        Tests::FakeCryptoConfigStringValue fakeCompliance{"gpg", "compliance", QStringLiteral("de-vs")};
        Tests::FakeCryptoConfigIntValue fakeDeVsCompliance{"gpg", "compliance_de_vs", 1};
        QVERIFY(DeVSCompliance::isActive());
        QVERIFY(DeVSCompliance::isCompliant());
        QVERIFY(!DeVSCompliance::isBetaCompliance());

        QVERIFY(!DeVSCompliance::algorithmIsCompliant("rsa2048"));
        QVERIFY(DeVSCompliance::algorithmIsCompliant("rsa3072"));

        QVERIFY(DeVSCompliance::compliantAlgorithms(GpgME::OpenPGP) != Kleo::availableAlgorithms(GpgME::OpenPGP));
        QVERIFY(DeVSCompliance::compliantAlgorithms(GpgME::CMS) != Kleo::availableAlgorithms(GpgME::CMS));

        QCOMPARE(DeVSCompliance::name(), u"VS-NfD compliant"_s);
        QCOMPARE(DeVSCompliance::name(true), u"VS-NfD compliant"_s);
        QCOMPARE(DeVSCompliance::name(false), u"Not VS-NfD compliant"_s);
    }

    void test_de_vs_compliance_active_and_compliant_gnupg_2_6()
    {
        Tests::FakeCryptoConfigStringValue fakeCompliance{"gpg", "compliance", QStringLiteral("de-vs")};
        // GnuPG 2.6 reports 23 as value for "compliance_de_vs"
        Tests::FakeCryptoConfigIntValue fakeDeVsCompliance{"gpg", "compliance_de_vs", 23};
        QVERIFY(DeVSCompliance::isActive());
        QVERIFY(DeVSCompliance::isCompliant());
        QVERIFY(!DeVSCompliance::isBetaCompliance());

        QCOMPARE(DeVSCompliance::name(), u"VS-NfD compliant"_s);
        QCOMPARE(DeVSCompliance::name(true), u"VS-NfD compliant"_s);
        QCOMPARE(DeVSCompliance::name(false), u"Not VS-NfD compliant"_s);
    }

    void test_de_vs_compliance_active_and_beta_compliant_gnupg_2_6()
    {
        Tests::FakeCryptoConfigStringValue fakeCompliance{"gpg", "compliance", QStringLiteral("de-vs")};
        // GnuPG 2.6 reports 2023 as value for "compliance_de_vs" if beta compliance is forced
        Tests::FakeCryptoConfigIntValue fakeDeVsCompliance{"gpg", "compliance_de_vs", 2023};
        QVERIFY(DeVSCompliance::isActive());
        QVERIFY(DeVSCompliance::isCompliant());
        QVERIFY(DeVSCompliance::isBetaCompliance());

        QCOMPARE(DeVSCompliance::name(), u"VS-NfD compliant (beta)"_s);
        QCOMPARE(DeVSCompliance::name(true), u"VS-NfD compliant (beta)"_s);
        QCOMPARE(DeVSCompliance::name(false), u"Not VS-NfD compliant"_s);
    }
};

QTEST_MAIN(ComplianceTest)
#include "compliancetest.moc"
