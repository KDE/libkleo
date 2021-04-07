/*
    autotests/keyresolvercoretest.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <Libkleo/KeyCache>
#include <Libkleo/KeyResolverCore>

#include <QObject>
#include <QTest>

#include <gpgme++/key.h>

#include <memory>

using namespace Kleo;
using namespace GpgME;

namespace QTest
{
template <>
inline bool qCompare(GpgME::UserID::Validity const &t1, GpgME::UserID::Validity const &t2, const char *actual, const char *expected,
                    const char *file, int line)
{
    return qCompare(int(t1), int(t2), actual, expected, file, line);
}
}

class KeyResolverCoreTest: public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void init()
    {
        mGnupgHome = QTest::qExtractTestData("/fixtures/keyresolvercoretest");
        qputenv("GNUPGHOME", mGnupgHome->path().toLocal8Bit());

        // hold a reference to the key cache to avoid rebuilding while the test is running
        mKeyCache = KeyCache::instance();
    }

    void cleanup()
    {
        // verify that nobody else holds a reference to the key cache
        QVERIFY(mKeyCache.use_count() == 1);
        mKeyCache.reset();

        mGnupgHome.reset();
    }

    void test_verify_test_keys()
    {
        {
            const Key openpgp = testKey("sender-mixed@example.net", OpenPGP);
            QVERIFY(openpgp.hasSecret() && openpgp.canEncrypt() && openpgp.canSign());
            QCOMPARE(openpgp.userID(0).validity(), UserID::Ultimate);
            const Key smime = testKey("sender-mixed@example.net", CMS);
            QVERIFY(smime.hasSecret() && smime.canEncrypt() && smime.canSign());
            QCOMPARE(smime.userID(0).validity(), UserID::Full);
        }
        {
            const Key openpgp = testKey("sender-openpgp@example.net", OpenPGP);
            QVERIFY(openpgp.hasSecret() && openpgp.canEncrypt() && openpgp.canSign());
            QCOMPARE(openpgp.userID(0).validity(), UserID::Ultimate);
        }
        {
            const Key smime = testKey("sender-smime@example.net", CMS);
            QVERIFY(smime.hasSecret() && smime.canEncrypt() && smime.canSign());
            QCOMPARE(smime.userID(0).validity(), UserID::Full);
        }
        {
            const Key openpgp = testKey("prefer-openpgp@example.net", OpenPGP);
            QVERIFY(openpgp.canEncrypt());
            QCOMPARE(openpgp.userID(0).validity(), UserID::Ultimate);
            const Key smime = testKey("prefer-openpgp@example.net", CMS);
            QVERIFY(smime.canEncrypt());
            QCOMPARE(smime.userID(0).validity(), UserID::Full);
        }
        {
            const Key openpgp = testKey("full-validity@example.net", OpenPGP);
            QVERIFY(openpgp.canEncrypt());
            QCOMPARE(openpgp.userID(0).validity(), UserID::Full);
            const Key smime = testKey("full-validity@example.net", CMS);
            QVERIFY(smime.canEncrypt());
            QCOMPARE(smime.userID(0).validity(), UserID::Full);
        }
        {
            const Key openpgp = testKey("prefer-smime@example.net", OpenPGP);
            QVERIFY(openpgp.canEncrypt());
            QCOMPARE(openpgp.userID(0).validity(), UserID::Marginal);
            const Key smime = testKey("prefer-smime@example.net", CMS);
            QVERIFY(smime.canEncrypt());
            QCOMPARE(smime.userID(0).validity(), UserID::Full);
        }
    }

    void test_openpgp_is_used_if_openpgp_only_and_smime_only_are_both_possible()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.signingKeys().value(OpenPGP).size(), 1);
        QCOMPARE(resolver.signingKeys().value(OpenPGP)[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(resolver.signingKeys().value(CMS).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("sender-mixed@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("sender-mixed@example.net")[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(resolver.encryptionKeys().value(CMS).size(), 0);
    }

    void test_openpgp_is_used_if_openpgp_only_and_smime_only_are_both_possible_with_preference_for_openpgp()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setPreferredProtocol(OpenPGP);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.signingKeys().value(OpenPGP).size(), 1);
        QCOMPARE(resolver.signingKeys().value(OpenPGP)[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(resolver.signingKeys().value(CMS).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("sender-mixed@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("sender-mixed@example.net")[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(resolver.encryptionKeys().value(CMS).size(), 0);
    }

    void test_smime_is_used_if_openpgp_only_and_smime_only_are_both_possible_with_preference_for_smime()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setPreferredProtocol(CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.signingKeys().value(OpenPGP).size(), 0);
        QCOMPARE(resolver.signingKeys().value(CMS).size(), 1);
        QCOMPARE(resolver.signingKeys().value(CMS)[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", CMS).primaryFingerprint());
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(CMS).size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("sender-mixed@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("sender-mixed@example.net")[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", CMS).primaryFingerprint());
    }

    void test_in_mixed_mode_keys_with_higher_validity_are_preferred()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false);
        resolver.setRecipients({"sender-openpgp@example.net", "sender-smime@example.net", "prefer-openpgp@example.net", "prefer-smime@example.net"});

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).size(), 4);
        QVERIFY(resolver.encryptionKeys().value(UnknownProtocol).contains("sender-openpgp@example.net"));
        QVERIFY(resolver.encryptionKeys().value(UnknownProtocol).contains("sender-smime@example.net"));
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("prefer-openpgp@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("prefer-openpgp@example.net")[0].primaryFingerprint(),
                 testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("prefer-smime@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("prefer-smime@example.net")[0].primaryFingerprint(),
                 testKey("prefer-smime@example.net", CMS).primaryFingerprint());
    }

    void test_reports_failure_if_both_protocols_are_allowed_but_no_keys_are_found_for_an_address()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false);
        resolver.setRecipients({"unknown@example.net"});

        const bool success = resolver.resolve();

        QVERIFY(!success);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(CMS).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).size(), 0);
    }

    void test_reports_failure_if_openpgp_is_requested_and_no_openpgp_keys_are_found_for_an_adddress()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false, OpenPGP);
        resolver.setRecipients({"sender-openpgp@example.net", "sender-smime@example.net"});

        const bool success = resolver.resolve();
        QVERIFY(!success);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).size(), 1);
        QVERIFY(resolver.encryptionKeys().value(OpenPGP).contains("sender-openpgp@example.net"));
        QCOMPARE(resolver.encryptionKeys().value(CMS).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).size(), 0);
    }

    void test_reports_failure_if_smime_is_requested_and_no_smime_keys_are_found_for_an_adddress()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false, CMS);
        resolver.setRecipients({"sender-openpgp@example.net", "sender-smime@example.net"});

        const bool success = resolver.resolve();
        QVERIFY(!success);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(CMS).size(), 1);
        QVERIFY(resolver.encryptionKeys().value(CMS).contains("sender-smime@example.net"));
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).size(), 0);
    }

    void test_reports_failure_if_mixed_protocols_are_not_allowed_but_needed()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false);
        resolver.setAllowMixedProtocols(false);
        resolver.setRecipients({"sender-openpgp@example.net", "sender-smime@example.net"});

        const bool success = resolver.resolve();
        QVERIFY(!success);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).size(), 1);
        QVERIFY(resolver.encryptionKeys().value(OpenPGP).contains("sender-openpgp@example.net"));
        QCOMPARE(resolver.encryptionKeys().value(CMS).size(), 1);
        QVERIFY(resolver.encryptionKeys().value(CMS).contains("sender-smime@example.net"));
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).size(), 0);
    }

    void test_openpgp_overrides_are_used_if_both_protocols_are_allowed()
    {
        const QString override = testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({"full-validity@example.net"});
        resolver.setOverrideKeys({{OpenPGP, {{QStringLiteral("Needs to be normalized <full-validity@example.net>"), {override}}}}});

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("full-validity@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("full-validity@example.net")[0].primaryFingerprint(), override);
        QCOMPARE(resolver.encryptionKeys().value(CMS).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("full-validity@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("full-validity@example.net")[0].primaryFingerprint(), override);
    }

    void test_openpgp_overrides_are_used_if_openpgp_only_is_requested()
    {
        const QString override = testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true, OpenPGP);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({"full-validity@example.net"});
        resolver.setOverrideKeys({{OpenPGP, {{QStringLiteral("Needs to be normalized <full-validity@example.net>"), {override}}}}});

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("full-validity@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("full-validity@example.net")[0].primaryFingerprint(), override);
        QCOMPARE(resolver.encryptionKeys().value(CMS).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).size(), 0);
    }

    void test_openpgp_overrides_are_ignored_if_smime_only_is_requested()
    {
        const QString override = testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true, CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({"full-validity@example.net"});
        resolver.setOverrideKeys({{OpenPGP, {{QStringLiteral("Needs to be normalized <full-validity@example.net>"), {override}}}}});

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("full-validity@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("full-validity@example.net")[0].primaryFingerprint(),
                 testKey("full-validity@example.net", CMS).primaryFingerprint());
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).size(), 0);
    }

    void test_smime_overrides_are_used_if_both_protocols_are_allowed()
    {
        const QString override = testKey("prefer-smime@example.net", CMS).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setPreferredProtocol(CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({"full-validity@example.net"});
        resolver.setOverrideKeys({{CMS, {{QStringLiteral("Needs to be normalized <full-validity@example.net>"), {override}}}}});

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("full-validity@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("full-validity@example.net")[0].primaryFingerprint(), override);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("full-validity@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("full-validity@example.net")[0].primaryFingerprint(), override);
    }

    void test_smime_overrides_are_used_if_smime_only_is_requested()
    {
        const QString override = testKey("prefer-smime@example.net", CMS).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true, CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({"full-validity@example.net"});
        resolver.setOverrideKeys({{CMS, {{QStringLiteral("Needs to be normalized <full-validity@example.net>"), {override}}}}});

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("full-validity@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("full-validity@example.net")[0].primaryFingerprint(), override);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).size(), 0);
    }

    void test_smime_overrides_are_ignored_if_openpgp_only_is_requested()
    {
        const QString override = testKey("prefer-smime@example.net", CMS).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true, OpenPGP);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({"full-validity@example.net"});
        resolver.setOverrideKeys({{CMS, {{QStringLiteral("Needs to be normalized <full-validity@example.net>"), {override}}}}});

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("full-validity@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("full-validity@example.net")[0].primaryFingerprint(),
                 testKey("full-validity@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(resolver.encryptionKeys().value(CMS).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).size(), 0);
    }

    void test_overrides_for_wrong_protocol_are_ignored()
    {
        const QString override1 = testKey("full-validity@example.net", CMS).primaryFingerprint();
        const QString override2 = testKey("full-validity@example.net", OpenPGP).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({"sender-openpgp@example.net", "sender-smime@example.net"});
        resolver.setOverrideKeys({{OpenPGP, {{QStringLiteral("Needs to be normalized <sender-openpgp@example.net>"), {override1}}}}});
        resolver.setOverrideKeys({{CMS, {{QStringLiteral("Needs to be normalized <sender-smime@example.net>"), {override2}}}}});

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("sender-openpgp@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("sender-openpgp@example.net")[0].primaryFingerprint(),
                 testKey("sender-openpgp@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("sender-smime@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("sender-smime@example.net")[0].primaryFingerprint(),
                 testKey("sender-smime@example.net", CMS).primaryFingerprint());
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("sender-openpgp@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("sender-openpgp@example.net")[0].primaryFingerprint(),
                 testKey("sender-openpgp@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("sender-smime@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("sender-smime@example.net")[0].primaryFingerprint(),
                 testKey("sender-smime@example.net", CMS).primaryFingerprint());
    }

    void test_openpgp_only_common_overrides_are_used_for_openpgp()
    {
        const QString override = testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({"sender-openpgp@example.net"});
        resolver.setOverrideKeys({{UnknownProtocol, {{QStringLiteral("Needs to be normalized <sender-openpgp@example.net>"), {override}}}}});

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("sender-openpgp@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("sender-openpgp@example.net")[0].primaryFingerprint(), override);
        QCOMPARE(resolver.encryptionKeys().value(CMS).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("sender-openpgp@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("sender-openpgp@example.net")[0].primaryFingerprint(), override);
    }

    void test_smime_only_common_overrides_are_used_for_smime()
    {
        const QString override = testKey("prefer-smime@example.net", CMS).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({"sender-smime@example.net"});
        resolver.setOverrideKeys({{UnknownProtocol, {{QStringLiteral("Needs to be normalized <sender-smime@example.net>"), {override}}}}});

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("sender-smime@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("sender-smime@example.net")[0].primaryFingerprint(), override);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("sender-smime@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("sender-smime@example.net")[0].primaryFingerprint(), override);
    }

    void test_mixed_protocol_common_overrides_override_protocol_specific_resolution()
    {
        const QString override1 = testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint();
        const QString override2 = testKey("prefer-smime@example.net", CMS).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setOverrideKeys({{UnknownProtocol, {{QStringLiteral("sender-mixed@example.net"), {override1, override2}}}}});

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(CMS).size(), 0);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("sender-mixed@example.net").size(), 2);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("sender-mixed@example.net")[0].primaryFingerprint(), override1);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("sender-mixed@example.net")[1].primaryFingerprint(), override2);
    }

    void test_common_overrides_override_protocol_specific_overrides()
    {
        const QString override1 = testKey("full-validity@example.net", OpenPGP).primaryFingerprint();
        const QString override2 = testKey("full-validity@example.net", CMS).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({"sender-openpgp@example.net", "sender-smime@example.net"});
        resolver.setOverrideKeys({
            {OpenPGP, {
                {QStringLiteral("sender-openpgp@example.net"), {testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint()}}
            }},
            {CMS, {
                {QStringLiteral("sender-smime@example.net"), {testKey("prefer-smime@example.net", CMS).primaryFingerprint()}}
            }},
            {UnknownProtocol, {
                {QStringLiteral("sender-openpgp@example.net"), {override1}},
                {QStringLiteral("sender-smime@example.net"), {override2}}
            }}
        });

        const bool success = resolver.resolve();

        QVERIFY(success);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("sender-openpgp@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(OpenPGP).value("sender-openpgp@example.net")[0].primaryFingerprint(), override1);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("sender-openpgp@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("sender-openpgp@example.net")[0].primaryFingerprint(), override1);
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("sender-smime@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(CMS).value("sender-smime@example.net")[0].primaryFingerprint(), override2);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("sender-smime@example.net").size(), 1);
        QCOMPARE(resolver.encryptionKeys().value(UnknownProtocol).value("sender-smime@example.net")[0].primaryFingerprint(), override2);
    }

    void test_reports_failure_if_openpgp_is_requested_but_common_overrides_require_smime()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false, OpenPGP);
        resolver.setRecipients({"sender-mixed@example.net"});
        resolver.setOverrideKeys({{UnknownProtocol, {
            {QStringLiteral("sender-mixed@example.net"), {testKey("prefer-smime@example.net", CMS).primaryFingerprint()}}
        }}});

        const bool success = resolver.resolve();
        QVERIFY(!success);
        QVERIFY(resolver.encryptionKeys().empty());
    }

    void test_reports_failure_if_smime_is_requested_but_common_overrides_require_openpgp()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false, CMS);
        resolver.setRecipients({"sender-mixed@example.net"});
        resolver.setOverrideKeys({{UnknownProtocol, {
            {QStringLiteral("sender-mixed@example.net"), {testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint()}}
        }}});

        const bool success = resolver.resolve();
        QVERIFY(!success);
        QVERIFY(resolver.encryptionKeys().empty());
    }

    void test_reports_failure_if_mixed_protocols_are_not_allowed_but_required_by_common_overrides()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false);
        resolver.setAllowMixedProtocols(false);
        resolver.setRecipients({"sender-mixed@example.net"});
        resolver.setOverrideKeys({{UnknownProtocol, {
            {QStringLiteral("sender-mixed@example.net"), {
                testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint(),
                testKey("prefer-smime@example.net", CMS).primaryFingerprint()
            }}
        }}});

        const bool success = resolver.resolve();
        QVERIFY(!success);
        QVERIFY(resolver.encryptionKeys().empty());
    }

private:
    Key testKey(const char *email, Protocol protocol = UnknownProtocol)
    {
        const std::vector<Key> keys = KeyCache::instance()->findByEMailAddress(email);
        for (const auto &key: keys) {
            if (protocol == UnknownProtocol || key.protocol() == protocol) {
                return key;
            }
        }
        return Key();
    }

private:
    QSharedPointer<QTemporaryDir> mGnupgHome;
    std::shared_ptr<const KeyCache> mKeyCache;
};

QTEST_MAIN(KeyResolverCoreTest)
#include "keyresolvercoretest.moc"
