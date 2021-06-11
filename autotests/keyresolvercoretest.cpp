/*
    autotests/keyresolvercoretest.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyGroup>
#include <Libkleo/KeyResolverCore>

#include <QObject>
#include <QProcess>
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

template <>
inline bool qCompare(int const &t1, KeyResolverCore::SolutionFlags const &t2, const char *actual, const char *expected,
                    const char *file, int line)
{
    return qCompare(int(t1), int(t2), actual, expected, file, line);
}

template <>
inline char *toString(const GpgME::Protocol &t)
{
    return qstrdup(Formatting::displayName(t).toLocal8Bit().constData());
}

template <>
inline bool qCompare(GpgME::Protocol const &t1, GpgME::Protocol const &t2, const char *actual, const char *expected,
                    const char *file, int line)
{
    return compare_helper(t1 == t2, "Compared values are not the same",
                          toString(t1), toString(t2), actual, expected, file, line);
}
}

namespace
{
KeyGroup createGroup(const QString &name,
                     const std::vector<Key> &keys = std::vector<Key>(),
                     KeyGroup::Source source = KeyGroup::ApplicationConfig,
                     const QString &configName = QString())
{
    const KeyGroup::Id groupId = (source == KeyGroup::ApplicationConfig) ?
                                 (configName.isEmpty() ? name : configName) :
                                 name;
    KeyGroup g(groupId, name, keys, source);
    return g;
}
}

class KeyResolverCoreTest: public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void init()
    {
        mGnupgHome = QTest::qExtractTestData(QStringLiteral("/fixtures/keyresolvercoretest"));
        qputenv("GNUPGHOME", mGnupgHome->path().toLocal8Bit());

        // hold a reference to the key cache to avoid rebuilding while the test is running
        mKeyCache = KeyCache::instance();
        // make sure that the key cache has been populated
        (void)mKeyCache->keys();
    }

    void cleanup()
    {
        // verify that nobody else holds a reference to the key cache
        QVERIFY(mKeyCache.use_count() == 1);
        mKeyCache.reset();

        // kill all running gpg daemons
        (void)QProcess::execute(QStringLiteral("gpgconf"), {"--kill", "all"});

        mGnupgHome.reset();
        qunsetenv("GNUPGHOME");
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
        resolver.setAllowMixedProtocols(false);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.solution.encryptionKeys.size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-mixed@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-mixed@example.net")[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.alternative.protocol, CMS);
        QCOMPARE(result.alternative.signingKeys.size(), 1);
        QCOMPARE(result.alternative.signingKeys[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", CMS).primaryFingerprint());
        QCOMPARE(result.alternative.encryptionKeys.size(), 1);
        QCOMPARE(result.alternative.encryptionKeys.value("sender-mixed@example.net").size(), 1);
        QCOMPARE(result.alternative.encryptionKeys.value("sender-mixed@example.net")[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", CMS).primaryFingerprint());
    }

    void test_openpgp_is_used_if_openpgp_only_and_smime_only_are_both_possible_with_preference_for_openpgp()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setAllowMixedProtocols(false);
        resolver.setPreferredProtocol(OpenPGP);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.solution.encryptionKeys.size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-mixed@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-mixed@example.net")[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.alternative.protocol, CMS);
        QCOMPARE(result.alternative.signingKeys.size(), 1);
        QCOMPARE(result.alternative.signingKeys[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", CMS).primaryFingerprint());
        QCOMPARE(result.alternative.encryptionKeys.size(), 1);
        QCOMPARE(result.alternative.encryptionKeys.value("sender-mixed@example.net").size(), 1);
        QCOMPARE(result.alternative.encryptionKeys.value("sender-mixed@example.net")[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", CMS).primaryFingerprint());
    }

    void test_smime_is_used_if_openpgp_only_and_smime_only_are_both_possible_with_preference_for_smime()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setAllowMixedProtocols(false);
        resolver.setPreferredProtocol(CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", CMS).primaryFingerprint());
        QCOMPARE(result.solution.encryptionKeys.size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-mixed@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-mixed@example.net")[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", CMS).primaryFingerprint());
        QCOMPARE(result.alternative.protocol, OpenPGP);
        QCOMPARE(result.alternative.signingKeys.size(), 1);
        QCOMPARE(result.alternative.signingKeys[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.alternative.encryptionKeys.size(), 1);
        QCOMPARE(result.alternative.encryptionKeys.value("sender-mixed@example.net").size(), 1);
        QCOMPARE(result.alternative.encryptionKeys.value("sender-mixed@example.net")[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
    }

    void test_in_mixed_mode_openpgp_is_used_if_openpgp_only_and_smime_only_are_both_possible()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.solution.encryptionKeys.size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-mixed@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-mixed@example.net")[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        // no alternative solution is proposed
        QCOMPARE(result.alternative.protocol, UnknownProtocol);
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
    }

    void test_in_mixed_mode_openpgp_is_used_if_openpgp_only_and_smime_only_are_both_possible_with_preference_for_openpgp()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setPreferredProtocol(OpenPGP);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.solution.encryptionKeys.size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-mixed@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-mixed@example.net")[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        // no alternative solution is proposed
        QCOMPARE(result.alternative.protocol, UnknownProtocol);
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
    }

    void test_in_mixed_mode_smime_is_used_if_openpgp_only_and_smime_only_are_both_possible_with_preference_for_smime()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setPreferredProtocol(CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", CMS).primaryFingerprint());
        QCOMPARE(result.solution.encryptionKeys.size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-mixed@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-mixed@example.net")[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", CMS).primaryFingerprint());
        // no alternative solution is proposed
        QCOMPARE(result.alternative.protocol, UnknownProtocol);
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
    }

    void test_in_mixed_mode_keys_with_higher_validity_are_preferred_if_both_protocols_are_needed()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false);
        resolver.setRecipients({"sender-openpgp@example.net", "sender-smime@example.net", "prefer-openpgp@example.net", "prefer-smime@example.net"});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::MixedProtocols);
        QCOMPARE(result.solution.protocol, UnknownProtocol);
        QCOMPARE(result.solution.encryptionKeys.size(), 4);
        QVERIFY(result.solution.encryptionKeys.contains("sender-openpgp@example.net"));
        QVERIFY(result.solution.encryptionKeys.contains("sender-smime@example.net"));
        QCOMPARE(result.solution.encryptionKeys.value("prefer-openpgp@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("prefer-openpgp@example.net")[0].primaryFingerprint(),
                 testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.solution.encryptionKeys.value("prefer-smime@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("prefer-smime@example.net")[0].primaryFingerprint(),
                 testKey("prefer-smime@example.net", CMS).primaryFingerprint());
        // no alternative solution is proposed
        QCOMPARE(result.alternative.protocol, UnknownProtocol);
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
    }

    void test_reports_unresolved_addresses_if_both_protocols_are_allowed_but_no_keys_are_found_for_an_address()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false);
        resolver.setRecipients({"unknown@example.net"});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::SomeUnresolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.encryptionKeys.value("unknown@example.net").size(), 0);
    }

    void test_reports_unresolved_addresses_if_openpgp_is_requested_and_no_openpgp_keys_are_found_for_an_address()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false, OpenPGP);
        resolver.setRecipients({"sender-openpgp@example.net", "sender-smime@example.net"});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::SomeUnresolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.encryptionKeys.size(), 2);
        QCOMPARE(result.solution.encryptionKeys.value("sender-openpgp@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-smime@example.net").size(), 0);
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
    }

    void test_reports_unresolved_addresses_if_smime_is_requested_and_no_smime_keys_are_found_for_an_address()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false, CMS);
        resolver.setRecipients({"sender-openpgp@example.net", "sender-smime@example.net"});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::SomeUnresolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.encryptionKeys.size(), 2);
        QCOMPARE(result.solution.encryptionKeys.value("sender-openpgp@example.net").size(), 0);
        QCOMPARE(result.solution.encryptionKeys.value("sender-smime@example.net").size(), 1);
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
    }

    void test_reports_unresolved_addresses_if_mixed_protocols_are_not_allowed_but_needed()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false);
        resolver.setAllowMixedProtocols(false);
        resolver.setRecipients({"sender-openpgp@example.net", "sender-smime@example.net"});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::SomeUnresolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.encryptionKeys.size(), 2);
        QCOMPARE(result.solution.encryptionKeys.value("sender-openpgp@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-smime@example.net").size(), 0);
        QCOMPARE(result.alternative.encryptionKeys.size(), 2);
        QCOMPARE(result.alternative.encryptionKeys.value("sender-openpgp@example.net").size(), 0);
        QCOMPARE(result.alternative.encryptionKeys.value("sender-smime@example.net").size(), 1);
    }

    void test_openpgp_overrides_are_used_if_both_protocols_are_allowed()
    {
        const QString override = testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setAllowMixedProtocols(false);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({"full-validity@example.net"});
        resolver.setOverrideKeys({{OpenPGP, {{QStringLiteral("Needs to be normalized <full-validity@example.net>"), {override}}}}});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.encryptionKeys.value("full-validity@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("full-validity@example.net")[0].primaryFingerprint(), override);
        QCOMPARE(result.alternative.encryptionKeys.value("full-validity@example.net").size(), 1);
        QCOMPARE(result.alternative.encryptionKeys.value("full-validity@example.net")[0].primaryFingerprint(),
                 testKey("full-validity@example.net", CMS).primaryFingerprint());
    }

    void test_openpgp_overrides_are_used_if_openpgp_only_is_requested()
    {
        const QString override = testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true, OpenPGP);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({"full-validity@example.net"});
        resolver.setOverrideKeys({{OpenPGP, {{QStringLiteral("Needs to be normalized <full-validity@example.net>"), {override}}}}});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.encryptionKeys.value("full-validity@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("full-validity@example.net")[0].primaryFingerprint(), override);
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
    }

    void test_openpgp_overrides_are_ignored_if_smime_only_is_requested()
    {
        const QString override = testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true, CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({"full-validity@example.net"});
        resolver.setOverrideKeys({{OpenPGP, {{QStringLiteral("Needs to be normalized <full-validity@example.net>"), {override}}}}});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.encryptionKeys.value("full-validity@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("full-validity@example.net")[0].primaryFingerprint(),
                 testKey("full-validity@example.net", CMS).primaryFingerprint());
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
    }

    void test_smime_overrides_are_used_if_both_protocols_are_allowed_and_smime_is_preferred()
    {
        const QString override = testKey("prefer-smime@example.net", CMS).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setAllowMixedProtocols(false);
        resolver.setPreferredProtocol(CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({"full-validity@example.net"});
        resolver.setOverrideKeys({{CMS, {{QStringLiteral("Needs to be normalized <full-validity@example.net>"), {override}}}}});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.encryptionKeys.value("full-validity@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("full-validity@example.net")[0].primaryFingerprint(), override);
        QCOMPARE(result.alternative.encryptionKeys.value("full-validity@example.net").size(), 1);
        QCOMPARE(result.alternative.encryptionKeys.value("full-validity@example.net")[0].primaryFingerprint(),
                 testKey("full-validity@example.net", OpenPGP).primaryFingerprint());
    }

    void test_smime_overrides_are_used_if_smime_only_is_requested()
    {
        const QString override = testKey("prefer-smime@example.net", CMS).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true, CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({"full-validity@example.net"});
        resolver.setOverrideKeys({{CMS, {{QStringLiteral("Needs to be normalized <full-validity@example.net>"), {override}}}}});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.encryptionKeys.value("full-validity@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("full-validity@example.net")[0].primaryFingerprint(), override);
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
    }

    void test_smime_overrides_are_ignored_if_openpgp_only_is_requested()
    {
        const QString override = testKey("prefer-smime@example.net", CMS).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true, OpenPGP);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({"full-validity@example.net"});
        resolver.setOverrideKeys({{CMS, {{QStringLiteral("Needs to be normalized <full-validity@example.net>"), {override}}}}});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.encryptionKeys.value("full-validity@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("full-validity@example.net")[0].primaryFingerprint(),
                 testKey("full-validity@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
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

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::MixedProtocols);
        QCOMPARE(result.solution.encryptionKeys.value("sender-openpgp@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-openpgp@example.net")[0].primaryFingerprint(),
                 testKey("sender-openpgp@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.solution.encryptionKeys.value("sender-smime@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-smime@example.net")[0].primaryFingerprint(),
                 testKey("sender-smime@example.net", CMS).primaryFingerprint());
    }

    void test_openpgp_only_common_overrides_are_used_for_openpgp()
    {
        const QString override = testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({"sender-openpgp@example.net"});
        resolver.setOverrideKeys({{UnknownProtocol, {{QStringLiteral("Needs to be normalized <sender-openpgp@example.net>"), {override}}}}});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.encryptionKeys.value("sender-openpgp@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-openpgp@example.net")[0].primaryFingerprint(), override);
    }

    void test_smime_only_common_overrides_are_used_for_smime()
    {
        const QString override = testKey("prefer-smime@example.net", CMS).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({"sender-smime@example.net"});
        resolver.setOverrideKeys({{UnknownProtocol, {{QStringLiteral("Needs to be normalized <sender-smime@example.net>"), {override}}}}});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.encryptionKeys.value("sender-smime@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-smime@example.net")[0].primaryFingerprint(), override);
    }

    void test_mixed_protocol_common_overrides_override_protocol_specific_resolution()
    {
        const QString override1 = testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint();
        const QString override2 = testKey("prefer-smime@example.net", CMS).primaryFingerprint();
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setOverrideKeys({{UnknownProtocol, {{QStringLiteral("sender-mixed@example.net"), {override1, override2}}}}});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::MixedProtocols);
        QCOMPARE(result.solution.encryptionKeys.value("sender-mixed@example.net").size(), 2);
        QCOMPARE(result.solution.encryptionKeys.value("sender-mixed@example.net")[0].primaryFingerprint(), override1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-mixed@example.net")[1].primaryFingerprint(), override2);
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

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::MixedProtocols);
        QCOMPARE(result.solution.encryptionKeys.value("sender-openpgp@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-openpgp@example.net")[0].primaryFingerprint(), override1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-smime@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-smime@example.net")[0].primaryFingerprint(), override2);
    }

    void test_reports_failure_if_openpgp_is_requested_but_common_overrides_require_smime()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false, OpenPGP);
        resolver.setRecipients({"sender-mixed@example.net"});
        resolver.setOverrideKeys({{UnknownProtocol, {
            {QStringLiteral("sender-mixed@example.net"), {testKey("prefer-smime@example.net", CMS).primaryFingerprint()}}
        }}});

        const auto result = resolver.resolve();

        QVERIFY(result.flags & KeyResolverCore::Error);
    }

    void test_reports_failure_if_smime_is_requested_but_common_overrides_require_openpgp()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false, CMS);
        resolver.setRecipients({"sender-mixed@example.net"});
        resolver.setOverrideKeys({{UnknownProtocol, {
            {QStringLiteral("sender-mixed@example.net"), {testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint()}}
        }}});

        const auto result = resolver.resolve();

        QVERIFY(result.flags & KeyResolverCore::Error);
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

        const auto result = resolver.resolve();

        QVERIFY(result.flags & KeyResolverCore::Error);
    }

    void test_groups__openpgp_only_mode__ignores_non_openpgp_only_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("group@example.net", {
                testKey("sender-openpgp@example.net", OpenPGP),
                testKey("sender-smime@example.net", CMS)
            }),
            createGroup("group@example.net", {
                testKey("prefer-smime@example.net", CMS)
            }),
            createGroup("group@example.net", {
                testKey("prefer-openpgp@example.net", OpenPGP),
            }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false, OpenPGP);
        resolver.setRecipients({"group@example.net"});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.encryptionKeys.value("group@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("group@example.net")[0].primaryFingerprint(),
                 testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint());
    }

    void test_groups__smime_only_mode__ignores_non_smime_only_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("group@example.net", {
                testKey("sender-openpgp@example.net", OpenPGP),
                testKey("sender-smime@example.net", CMS)
            }),
            createGroup("group@example.net", {
                testKey("prefer-smime@example.net", CMS)
            }),
            createGroup("group@example.net", {
                testKey("prefer-openpgp@example.net", OpenPGP),
            }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false, CMS);
        resolver.setRecipients({"group@example.net"});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.encryptionKeys.value("group@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("group@example.net")[0].primaryFingerprint(),
                 testKey("prefer-smime@example.net", CMS).primaryFingerprint());
    }

    void test_groups__single_protocol_mode__ignores_mixed_protocol_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-mixed@example.net", {
                testKey("sender-openpgp@example.net", OpenPGP),
                testKey("sender-smime@example.net", CMS)
            }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false);
        resolver.setAllowMixedProtocols(false);
        resolver.setRecipients({"sender-mixed@example.net"});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.encryptionKeys.value("sender-mixed@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("sender-mixed@example.net")[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
    }

    void test_groups__mixed_mode__single_protocol_groups_are_preferred_over_mixed_protocol_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("group@example.net", {
                testKey("sender-openpgp@example.net", OpenPGP),
                testKey("sender-smime@example.net", CMS)
            }),
            createGroup("group@example.net", {
                testKey("prefer-smime@example.net", CMS)
            }),
            createGroup("group@example.net", {
                testKey("prefer-openpgp@example.net", OpenPGP),
            }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false);
        resolver.setRecipients({"group@example.net"});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.encryptionKeys.value("group@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("group@example.net")[0].primaryFingerprint(),
                 testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint());
    }

    void test_groups__mixed_mode__openpgp_only_group_preferred_over_mixed_protocol_group()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("group@example.net", {
                testKey("sender-openpgp@example.net", OpenPGP),
                testKey("sender-smime@example.net", CMS)
            }),
            createGroup("group@example.net", {
                testKey("sender-openpgp@example.net", OpenPGP)
            }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false);
        resolver.setRecipients({"group@example.net"});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.encryptionKeys.value("group@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("group@example.net")[0].primaryFingerprint(),
                 testKey("sender-openpgp@example.net", OpenPGP).primaryFingerprint());
    }

    void test_groups__mixed_mode__smime_only_group_preferred_over_mixed_protocol_group()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("group@example.net", {
                testKey("sender-openpgp@example.net", OpenPGP),
                testKey("sender-smime@example.net", CMS)
            }),
            createGroup("group@example.net", {
                testKey("sender-smime@example.net", CMS)
            }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false);
        resolver.setRecipients({"group@example.net"});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.encryptionKeys.value("group@example.net").size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value("group@example.net")[0].primaryFingerprint(),
                 testKey("sender-smime@example.net", CMS).primaryFingerprint());
    }

    void test_groups__mixed_mode__mixed_protocol_groups_are_used()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-mixed@example.net", {
                testKey("sender-openpgp@example.net", OpenPGP),
                testKey("sender-smime@example.net", CMS)
            }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false);
        resolver.setRecipients({"sender-mixed@example.net"});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::MixedProtocols);
        QCOMPARE(result.solution.protocol, UnknownProtocol);
        QCOMPARE(result.solution.encryptionKeys.value("sender-mixed@example.net").size(), 2);
    }

    void test_groups_for_signing_key__openpgp_only_mode__prefers_groups_over_keys()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-mixed@example.net", {
                testKey("sender-openpgp@example.net", OpenPGP),
            }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/ false, /*sign=*/ true, OpenPGP);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(),
                 testKey("sender-openpgp@example.net", OpenPGP).primaryFingerprint());
    }

    void test_groups_for_signing_key__openpgp_only_mode__prefers_single_protocol_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-alias@example.net", {
                testKey("sender-mixed@example.net", OpenPGP),
                testKey("sender-mixed@example.net", CMS),
            }),
            createGroup("sender-alias@example.net", {
                testKey("sender-openpgp@example.net", OpenPGP),
            }),
            createGroup("sender-alias@example.net", {
                testKey("sender-smime@example.net", CMS),
            }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/ false, /*sign=*/ true, OpenPGP);
        resolver.setSender(QStringLiteral("sender-alias@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(),
                 testKey("sender-openpgp@example.net", OpenPGP).primaryFingerprint());
    }

    void test_groups_for_signing_key__openpgp_only_mode__takes_key_of_mixed_protocol_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-alias@example.net", {
                testKey("sender-mixed@example.net", OpenPGP),
                testKey("sender-mixed@example.net", CMS),
            }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/ false, /*sign=*/ true, OpenPGP);
        resolver.setSender(QStringLiteral("sender-alias@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
    }

    void test_groups_for_signing_key__smime_only_mode__prefers_groups_over_keys()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-mixed@example.net", {
                testKey("sender-smime@example.net", CMS),
            }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/ false, /*sign=*/ true, CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(),
                 testKey("sender-smime@example.net", CMS).primaryFingerprint());
    }

    void test_groups_for_signing_key__smime_only_mode__prefers_single_protocol_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-alias@example.net", {
                testKey("sender-mixed@example.net", OpenPGP),
                testKey("sender-mixed@example.net", CMS),
            }),
            createGroup("sender-alias@example.net", {
                testKey("sender-openpgp@example.net", OpenPGP),
            }),
            createGroup("sender-alias@example.net", {
                testKey("sender-smime@example.net", CMS),
            }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/ false, /*sign=*/ true, CMS);
        resolver.setSender(QStringLiteral("sender-alias@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(),
                 testKey("sender-smime@example.net", CMS).primaryFingerprint());
    }

    void test_groups_for_signing_key__smime_only_mode__takes_key_of_mixed_protocol_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-alias@example.net", {
                testKey("sender-mixed@example.net", OpenPGP),
                testKey("sender-mixed@example.net", CMS),
            }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/ false, /*sign=*/ true, CMS);
        resolver.setSender(QStringLiteral("sender-alias@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", CMS).primaryFingerprint());
    }

    void test_groups_for_signing_key__single_protocol_mode__prefers_groups_over_keys()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-mixed@example.net", {
                testKey("sender-openpgp@example.net", OpenPGP),
                testKey("sender-smime@example.net", CMS),
            }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/ false, /*sign=*/ true);
        resolver.setAllowMixedProtocols(false);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(),
                 testKey("sender-openpgp@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.alternative.signingKeys.size(), 1);
        QCOMPARE(result.alternative.signingKeys[0].primaryFingerprint(),
                 testKey("sender-smime@example.net", CMS).primaryFingerprint());
    }

    void test_groups_for_signing_key__single_protocol_mode__prefers_single_protocol_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-alias@example.net", {
                testKey("sender-mixed@example.net", OpenPGP),
                testKey("sender-mixed@example.net", CMS),
            }),
            createGroup("sender-alias@example.net", {
                testKey("sender-openpgp@example.net", OpenPGP),
            }),
            createGroup("sender-alias@example.net", {
                testKey("sender-smime@example.net", CMS),
            }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/ false, /*sign=*/ true);
        resolver.setAllowMixedProtocols(false);
        resolver.setSender(QStringLiteral("sender-alias@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(),
                 testKey("sender-openpgp@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.alternative.signingKeys.size(), 1);
        QCOMPARE(result.alternative.signingKeys[0].primaryFingerprint(),
                 testKey("sender-smime@example.net", CMS).primaryFingerprint());
    }

    void test_groups_for_signing_key__mixed_mode__prefers_groups_over_keys()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-mixed@example.net", {
                testKey("sender-openpgp@example.net", OpenPGP),
                testKey("sender-smime@example.net", CMS),
            }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/ false, /*sign=*/ true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(),
                 testKey("sender-openpgp@example.net", OpenPGP).primaryFingerprint());
    }

    void test_groups_for_signing_key__mixed_mode_with_smime_preferred__prefers_groups_over_keys()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-mixed@example.net", {
                testKey("sender-openpgp@example.net", OpenPGP),
                testKey("sender-smime@example.net", CMS),
            }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/ false, /*sign=*/ true);
        resolver.setPreferredProtocol(CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(),
                 testKey("sender-smime@example.net", CMS).primaryFingerprint());
    }

    void test_groups_for_signing_key__mixed_mode__prefers_single_protocol_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-alias@example.net", {
                testKey("sender-mixed@example.net", OpenPGP),
                testKey("sender-mixed@example.net", CMS),
            }),
            createGroup("sender-alias@example.net", {
                testKey("sender-openpgp@example.net", OpenPGP),
            }),
            createGroup("sender-alias@example.net", {
                testKey("sender-smime@example.net", CMS),
            }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/ false, /*sign=*/ true);
        resolver.setSender(QStringLiteral("sender-alias@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(),
                 testKey("sender-openpgp@example.net", OpenPGP).primaryFingerprint());
    }

    void test_groups_for_signing_key__mixed_mode_with_smime_preferred__prefers_single_protocol_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-alias@example.net", {
                testKey("sender-mixed@example.net", OpenPGP),
                testKey("sender-mixed@example.net", CMS),
            }),
            createGroup("sender-alias@example.net", {
                testKey("sender-openpgp@example.net", OpenPGP),
            }),
            createGroup("sender-alias@example.net", {
                testKey("sender-smime@example.net", CMS),
            }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/ false, /*sign=*/ true);
        resolver.setPreferredProtocol(CMS);
        resolver.setSender(QStringLiteral("sender-alias@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(),
                 testKey("sender-smime@example.net", CMS).primaryFingerprint());
    }

    void test_sender_is_set__encrypt_only_mode()
    {
        KeyResolverCore resolver(/*encrypt=*/ true, /*sign=*/ false);
        resolver.setRecipients({"prefer-openpgp@example.net", "prefer-smime@example.net"});
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(resolver.normalizedSender(), QLatin1String{"sender-mixed@example.net"});
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
        qWarning() << "No" << Formatting::displayName(protocol) << "test key found for" << email;
        return {};
    }

private:
    QSharedPointer<QTemporaryDir> mGnupgHome;
    std::shared_ptr<const KeyCache> mKeyCache;
};

QTEST_MAIN(KeyResolverCoreTest)
#include "keyresolvercoretest.moc"
