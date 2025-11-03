/*
    autotests/keyresolvercoretest.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "testhelpers.h"

#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyGroup>
#include <Libkleo/KeyResolverCore>
#include <Libkleo/Test>

#include <QFile>
#include <QObject>
#include <QProcess>
#include <QTest>

#include <gpgme++/key.h>

#include <memory>

using namespace Kleo;
using namespace GpgME;
using namespace Qt::Literals::StringLiterals;

namespace QTest
{
template<>
inline bool qCompare(GpgME::UserID::Validity const &t1, GpgME::UserID::Validity const &t2, const char *actual, const char *expected, const char *file, int line)
{
    return qCompare(int(t1), int(t2), actual, expected, file, line);
}

template<>
inline char *toString(const KeyResolverCore::SolutionFlags &flags)
{
    QStringList v;
    if (flags & KeyResolverCore::AllResolved) {
        v.append(QStringLiteral("KeyResolverCore::AllResolved"));
    } else {
        v.append(QStringLiteral("KeyResolverCore::SomeUnresolved"));
    }
    if ((flags & KeyResolverCore::MixedProtocols) == KeyResolverCore::MixedProtocols) {
        v.append(QStringLiteral("KeyResolverCore::MixedProtocols"));
    } else if (flags & KeyResolverCore::OpenPGPOnly) {
        v.append(QStringLiteral("KeyResolverCore::OpenPGPOnly"));
    } else if (flags & KeyResolverCore::CMSOnly) {
        v.append(QStringLiteral("KeyResolverCore::CMSOnly"));
    }
    return qstrdup(v.join(QStringLiteral(" | ")).toLocal8Bit().constData());
}

template<>
inline bool qCompare(int const &t1, KeyResolverCore::SolutionFlags const &t2, const char *actual, const char *expected, const char *file, int line)
{
    return qCompare(static_cast<KeyResolverCore::SolutionFlags>(t1), t2, actual, expected, file, line);
}

template<>
inline char *toString(const GpgME::Protocol &t)
{
    return qstrdup(Formatting::displayName(t).toLocal8Bit().constData());
}

template<>
inline bool qCompare(GpgME::Protocol const &t1, GpgME::Protocol const &t2, const char *actual, const char *expected, const char *file, int line)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 8, 0)
    auto formatter = Internal::genericToString<GpgME::Protocol>;
    return compare_helper(t1 == t2, "Compared values are not the same", &t1, &t2, formatter, formatter, actual, expected, file, line);
#else
    auto actualVal = [&t1] {
        return toString(t1);
    };
    auto expectedVal = [&t2] {
        return toString(t2);
    };
    return compare_helper(t1 == t2, "Compared values are not the same", actualVal, expectedVal, actual, expected, file, line);
#endif
}
}

namespace
{
KeyGroup createGroup(const char *groupName,
                     const std::vector<Key> &keys = std::vector<Key>(),
                     KeyGroup::Source source = KeyGroup::ApplicationConfig,
                     const char *configName = nullptr)
{
    const QString name = QString::fromLatin1(groupName);
    const KeyGroup::Id groupId = ((source == KeyGroup::ApplicationConfig) //
                                      ? ((!configName || !*configName) ? name : QString::fromLatin1(configName))
                                      : name);
    KeyGroup g(groupId, name, keys, source);
    return g;
}
}

class KeyResolverCoreTest : public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void initTestCase()
    {
        if (qgetenv("CI_RUNNER_EXECUTABLE_ARCH").contains("freebsd")) {
            QSKIP("On FreeBSD, this test often takes longer than 120 seconds, times out and fails the build.");
        }
        // Check if we need to create GnuPG's socket directory before running the tests to avoid
        // a race between gpg and gpgsm (see https://dev.gnupg.org/T7332).
        // On CI /run/user doesn't exist so that GnuPG falls back to using GNUPGHOME as socket directory
        // which is already created by QTest::qExtractTestData (and running `gpgconf --create-socketdir`
        // would fail).
        if (QFile::exists(u"/run/user"_s)) {
            // The race is fixed in GnuPG 2.5.2, 2.4.6, and 2.2.45
            mNeedToCreateSocketDir = !(engineIsVersion(2, 5, 2) || //
                                       (engineIsVersion(2, 4, 6) && !engineIsVersion(2, 5, 0)) || //
                                       (engineIsVersion(2, 2, 45) && !engineIsVersion(2, 3, 0)));
        }
    }

    void init()
    {
        mGnupgHome = QTest::qExtractTestData(QStringLiteral("/fixtures/keyresolvercoretest"));
        qputenv("GNUPGHOME", mGnupgHome->path().toLocal8Bit());

        if (mNeedToCreateSocketDir) {
            int exitCode = QProcess::execute(Kleo::gpgConfPath(), {u"--create-socketdir"_s});
            QCOMPARE(exitCode, 0);
        }

        // hold a reference to the key cache to avoid rebuilding while the test is running
        mKeyCache = KeyCache::instance();
        // make sure that the key cache has been populated
        (void)mKeyCache->keys();
    }

    void cleanup()
    {
        // verify that nobody else holds a reference to the key cache
        QCOMPARE(mKeyCache.use_count(), 1);
        mKeyCache.reset();

        // kill all running gpg daemons
        (void)QProcess::execute(QStringLiteral("gpgconf"), {u"--kill"_s, u"all"_s});

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
        {
            const Key openpgp = testKey("openpgp-only@example.net", OpenPGP);
            QVERIFY(openpgp.canEncrypt());
            QCOMPARE(openpgp.userID(0).validity(), UserID::Full);
            const Key smime = testKey("openpgp-only@example.net", CMS);
            QVERIFY(smime.isNull());
        }
        {
            const Key openpgp = testKey("smime-only@example.net", OpenPGP);
            QVERIFY(openpgp.isNull());
            const Key smime = testKey("smime-only@example.net", CMS);
            QVERIFY(smime.canEncrypt());
            QCOMPARE(smime.userID(0).validity(), UserID::Full);
        }
    }

    void test_openpgp_is_used_if_openpgp_only_and_smime_only_are_both_possible()
    {
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/true);
        resolver.setAllowMixedProtocols(false);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.solution.encryptionKeys.size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-mixed@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-mixed@example.net"_s)[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.alternative.protocol, CMS);
        QCOMPARE(result.alternative.signingKeys.size(), 1);
        QCOMPARE(result.alternative.signingKeys[0].primaryFingerprint(), testKey("sender-mixed@example.net", CMS).primaryFingerprint());
        QCOMPARE(result.alternative.encryptionKeys.size(), 1);
        QCOMPARE(result.alternative.encryptionKeys.value(u"sender-mixed@example.net"_s).size(), 1);
        QCOMPARE(result.alternative.encryptionKeys.value(u"sender-mixed@example.net"_s)[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", CMS).primaryFingerprint());
    }

    void test_openpgp_is_used_if_openpgp_only_and_smime_only_are_both_possible_with_preference_for_openpgp()
    {
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/true);
        resolver.setAllowMixedProtocols(false);
        resolver.setPreferredProtocol(OpenPGP);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.solution.encryptionKeys.size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-mixed@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-mixed@example.net"_s)[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.alternative.protocol, CMS);
        QCOMPARE(result.alternative.signingKeys.size(), 1);
        QCOMPARE(result.alternative.signingKeys[0].primaryFingerprint(), testKey("sender-mixed@example.net", CMS).primaryFingerprint());
        QCOMPARE(result.alternative.encryptionKeys.size(), 1);
        QCOMPARE(result.alternative.encryptionKeys.value(u"sender-mixed@example.net"_s).size(), 1);
        QCOMPARE(result.alternative.encryptionKeys.value(u"sender-mixed@example.net"_s)[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", CMS).primaryFingerprint());
    }

    void test_smime_is_used_if_openpgp_only_and_smime_only_are_both_possible_with_preference_for_smime()
    {
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/true);
        resolver.setAllowMixedProtocols(false);
        resolver.setPreferredProtocol(CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-mixed@example.net", CMS).primaryFingerprint());
        QCOMPARE(result.solution.encryptionKeys.size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-mixed@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-mixed@example.net"_s)[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", CMS).primaryFingerprint());
        QCOMPARE(result.alternative.protocol, OpenPGP);
        QCOMPARE(result.alternative.signingKeys.size(), 1);
        QCOMPARE(result.alternative.signingKeys[0].primaryFingerprint(), testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.alternative.encryptionKeys.size(), 1);
        QCOMPARE(result.alternative.encryptionKeys.value(u"sender-mixed@example.net"_s).size(), 1);
        QCOMPARE(result.alternative.encryptionKeys.value(u"sender-mixed@example.net"_s)[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
    }

    void test_in_mixed_mode_openpgp_is_used_if_openpgp_only_and_smime_only_are_both_possible()
    {
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.solution.encryptionKeys.size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-mixed@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-mixed@example.net"_s)[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        // no alternative solution is proposed
        QCOMPARE(result.alternative.protocol, UnknownProtocol);
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
    }

    void test_in_mixed_mode_openpgp_is_used_if_openpgp_only_and_smime_only_are_both_possible_with_preference_for_openpgp()
    {
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/true);
        resolver.setPreferredProtocol(OpenPGP);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.solution.encryptionKeys.size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-mixed@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-mixed@example.net"_s)[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
        // no alternative solution is proposed
        QCOMPARE(result.alternative.protocol, UnknownProtocol);
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
    }

    void test_in_mixed_mode_smime_is_used_if_openpgp_only_and_smime_only_are_both_possible_with_preference_for_smime()
    {
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/true);
        resolver.setPreferredProtocol(CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-mixed@example.net", CMS).primaryFingerprint());
        QCOMPARE(result.solution.encryptionKeys.size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-mixed@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-mixed@example.net"_s)[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", CMS).primaryFingerprint());
        // no alternative solution is proposed
        QCOMPARE(result.alternative.protocol, UnknownProtocol);
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
    }

    void test_in_mixed_mode_keys_with_higher_validity_are_preferred_if_both_protocols_are_needed()
    {
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/false);
        resolver.setRecipients(
            {u"sender-openpgp@example.net"_s, u"sender-smime@example.net"_s, u"prefer-openpgp@example.net"_s, u"prefer-smime@example.net"_s});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::MixedProtocols);
        QCOMPARE(result.solution.protocol, UnknownProtocol);
        QCOMPARE(result.solution.encryptionKeys.size(), 4);
        QVERIFY(result.solution.encryptionKeys.contains(u"sender-openpgp@example.net"_s));
        QVERIFY(result.solution.encryptionKeys.contains(u"sender-smime@example.net"_s));
        QCOMPARE(result.solution.encryptionKeys.value(u"prefer-openpgp@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"prefer-openpgp@example.net"_s)[0].primaryFingerprint(),
                 testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.solution.encryptionKeys.value(u"prefer-smime@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"prefer-smime@example.net"_s)[0].primaryFingerprint(),
                 testKey("prefer-smime@example.net", CMS).primaryFingerprint());
        // no alternative solution is proposed
        QCOMPARE(result.alternative.protocol, UnknownProtocol);
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
    }

    void test_reports_unresolved_addresses_if_both_protocols_are_allowed_but_no_keys_are_found_for_an_address()
    {
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/false);
        resolver.setRecipients({u"unknown@example.net"_s});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::SomeUnresolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.encryptionKeys.value(u"unknown@example.net"_s).size(), 0);
    }

    void test_reports_unresolved_addresses_if_openpgp_is_requested_and_no_openpgp_keys_are_found_for_an_address()
    {
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/false, OpenPGP);
        resolver.setRecipients({u"sender-openpgp@example.net"_s, u"sender-smime@example.net"_s});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::SomeUnresolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.encryptionKeys.size(), 2);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-openpgp@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-smime@example.net"_s).size(), 0);
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
    }

    void test_reports_unresolved_addresses_if_smime_is_requested_and_no_smime_keys_are_found_for_an_address()
    {
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/false, CMS);
        resolver.setRecipients({u"sender-openpgp@example.net"_s, u"sender-smime@example.net"_s});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::SomeUnresolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.encryptionKeys.size(), 2);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-openpgp@example.net"_s).size(), 0);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-smime@example.net"_s).size(), 1);
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
    }

    void test_reports_unresolved_addresses_if_mixed_protocols_are_not_allowed_but_needed()
    {
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/false);
        resolver.setAllowMixedProtocols(false);
        resolver.setRecipients({u"sender-openpgp@example.net"_s, u"sender-smime@example.net"_s});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::SomeUnresolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.encryptionKeys.size(), 2);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-openpgp@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-smime@example.net"_s).size(), 0);
        QCOMPARE(result.alternative.encryptionKeys.size(), 2);
        QCOMPARE(result.alternative.encryptionKeys.value(u"sender-openpgp@example.net"_s).size(), 0);
        QCOMPARE(result.alternative.encryptionKeys.value(u"sender-smime@example.net"_s).size(), 1);
    }

    void test_openpgp_overrides_are_used_if_both_protocols_are_allowed()
    {
        const QString override = QString::fromLatin1(testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint());
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/true);
        resolver.setAllowMixedProtocols(false);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({u"full-validity@example.net"_s});
        resolver.setOverrideKeys({{OpenPGP, {{QStringLiteral("Needs to be normalized <full-validity@example.net>"), {override}}}}});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.encryptionKeys.value(u"full-validity@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"full-validity@example.net"_s)[0].primaryFingerprint(), override);
        QCOMPARE(result.alternative.encryptionKeys.value(u"full-validity@example.net"_s).size(), 1);
        QCOMPARE(result.alternative.encryptionKeys.value(u"full-validity@example.net"_s)[0].primaryFingerprint(),
                 testKey("full-validity@example.net", CMS).primaryFingerprint());
    }

    void test_openpgp_overrides_are_used_if_openpgp_only_is_requested()
    {
        const QString override = QString::fromLatin1(testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint());
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/true, OpenPGP);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({u"full-validity@example.net"_s});
        resolver.setOverrideKeys({{OpenPGP, {{QStringLiteral("Needs to be normalized <full-validity@example.net>"), {override}}}}});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.encryptionKeys.value(u"full-validity@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"full-validity@example.net"_s)[0].primaryFingerprint(), override);
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
    }

    void test_openpgp_overrides_are_ignored_if_smime_only_is_requested()
    {
        const QString override = QString::fromLatin1(testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint());
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/true, CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({u"full-validity@example.net"_s});
        resolver.setOverrideKeys({{OpenPGP, {{QStringLiteral("Needs to be normalized <full-validity@example.net>"), {override}}}}});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.encryptionKeys.value(u"full-validity@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"full-validity@example.net"_s)[0].primaryFingerprint(),
                 testKey("full-validity@example.net", CMS).primaryFingerprint());
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
    }

    void test_smime_overrides_are_used_if_both_protocols_are_allowed_and_smime_is_preferred()
    {
        const QString override = QString::fromLatin1(testKey("prefer-smime@example.net", CMS).primaryFingerprint());
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/true);
        resolver.setAllowMixedProtocols(false);
        resolver.setPreferredProtocol(CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({u"full-validity@example.net"_s});
        resolver.setOverrideKeys({{CMS, {{QStringLiteral("Needs to be normalized <full-validity@example.net>"), {override}}}}});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.encryptionKeys.value(u"full-validity@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"full-validity@example.net"_s)[0].primaryFingerprint(), override);
        QCOMPARE(result.alternative.encryptionKeys.value(u"full-validity@example.net"_s).size(), 1);
        QCOMPARE(result.alternative.encryptionKeys.value(u"full-validity@example.net"_s)[0].primaryFingerprint(),
                 testKey("full-validity@example.net", OpenPGP).primaryFingerprint());
    }

    void test_smime_overrides_are_used_if_smime_only_is_requested()
    {
        const QString override = QString::fromLatin1(testKey("prefer-smime@example.net", CMS).primaryFingerprint());
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/true, CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({u"full-validity@example.net"_s});
        resolver.setOverrideKeys({{CMS, {{QStringLiteral("Needs to be normalized <full-validity@example.net>"), {override}}}}});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.encryptionKeys.value(u"full-validity@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"full-validity@example.net"_s)[0].primaryFingerprint(), override);
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
    }

    void test_smime_overrides_are_ignored_if_openpgp_only_is_requested()
    {
        const QString override = QString::fromLatin1(testKey("prefer-smime@example.net", CMS).primaryFingerprint());
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/true, OpenPGP);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({u"full-validity@example.net"_s});
        resolver.setOverrideKeys({{CMS, {{QStringLiteral("Needs to be normalized <full-validity@example.net>"), {override}}}}});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.encryptionKeys.value(u"full-validity@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"full-validity@example.net"_s)[0].primaryFingerprint(),
                 testKey("full-validity@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.alternative.encryptionKeys.size(), 0);
    }

    void test_overrides_for_wrong_protocol_are_ignored()
    {
        const QString override1 = QString::fromLatin1(testKey("full-validity@example.net", CMS).primaryFingerprint());
        const QString override2 = QString::fromLatin1(testKey("full-validity@example.net", OpenPGP).primaryFingerprint());
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({u"sender-openpgp@example.net"_s, u"sender-smime@example.net"_s});
        resolver.setOverrideKeys({{OpenPGP, {{QStringLiteral("Needs to be normalized <sender-openpgp@example.net>"), {override1}}}}});
        resolver.setOverrideKeys({{CMS, {{QStringLiteral("Needs to be normalized <sender-smime@example.net>"), {override2}}}}});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::MixedProtocols);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-openpgp@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-openpgp@example.net"_s)[0].primaryFingerprint(),
                 testKey("sender-openpgp@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-smime@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-smime@example.net"_s)[0].primaryFingerprint(),
                 testKey("sender-smime@example.net", CMS).primaryFingerprint());
    }

    void test_openpgp_only_common_overrides_are_used_for_openpgp()
    {
        const QString override = QString::fromLatin1(testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint());
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({u"sender-openpgp@example.net"_s});
        resolver.setOverrideKeys({{UnknownProtocol, {{QStringLiteral("Needs to be normalized <sender-openpgp@example.net>"), {override}}}}});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-openpgp@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-openpgp@example.net"_s)[0].primaryFingerprint(), override);
    }

    void test_smime_only_common_overrides_are_used_for_smime()
    {
        const QString override = QString::fromLatin1(testKey("prefer-smime@example.net", CMS).primaryFingerprint());
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({u"sender-smime@example.net"_s});
        resolver.setOverrideKeys({{UnknownProtocol, {{QStringLiteral("Needs to be normalized <sender-smime@example.net>"), {override}}}}});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-smime@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-smime@example.net"_s)[0].primaryFingerprint(), override);
    }

    void test_mixed_protocol_common_overrides_override_protocol_specific_resolution()
    {
        const QString override1 = QString::fromLatin1(testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint());
        const QString override2 = QString::fromLatin1(testKey("prefer-smime@example.net", CMS).primaryFingerprint());
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setOverrideKeys({{UnknownProtocol, {{QStringLiteral("sender-mixed@example.net"), {override1, override2}}}}});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::MixedProtocols);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-mixed@example.net"_s).size(), 2);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-mixed@example.net"_s)[0].primaryFingerprint(), override1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-mixed@example.net"_s)[1].primaryFingerprint(), override2);
    }

    void test_common_overrides_override_protocol_specific_overrides()
    {
        const QString override1 = QString::fromLatin1(testKey("full-validity@example.net", OpenPGP).primaryFingerprint());
        const QString override2 = QString::fromLatin1(testKey("full-validity@example.net", CMS).primaryFingerprint());
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));
        resolver.setRecipients({u"sender-openpgp@example.net"_s, u"sender-smime@example.net"_s});
        resolver.setOverrideKeys({
            {
                OpenPGP,
                {
                    {QStringLiteral("sender-openpgp@example.net"), {QString::fromLatin1(testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint())}},
                },
            },
            {
                CMS,
                {
                    {QStringLiteral("sender-smime@example.net"), {QString::fromLatin1(testKey("prefer-smime@example.net", CMS).primaryFingerprint())}},
                },
            },
            {
                UnknownProtocol,
                {
                    {QStringLiteral("sender-openpgp@example.net"), {override1}},
                    {QStringLiteral("sender-smime@example.net"), {override2}},
                },
            },
        });

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::MixedProtocols);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-openpgp@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-openpgp@example.net"_s)[0].primaryFingerprint(), override1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-smime@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-smime@example.net"_s)[0].primaryFingerprint(), override2);
    }

    void test_reports_failure_if_openpgp_is_requested_but_common_overrides_require_smime()
    {
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/false, OpenPGP);
        resolver.setRecipients({u"sender-mixed@example.net"_s});
        resolver.setOverrideKeys({{
            UnknownProtocol,
            {{QStringLiteral("sender-mixed@example.net"), {QString::fromLatin1(testKey("prefer-smime@example.net", CMS).primaryFingerprint())}}},
        }});

        const auto result = resolver.resolve();

        QVERIFY(result.flags & KeyResolverCore::Error);
    }

    void test_reports_failure_if_smime_is_requested_but_common_overrides_require_openpgp()
    {
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/false, CMS);
        resolver.setRecipients({u"sender-mixed@example.net"_s});
        resolver.setOverrideKeys({{
            UnknownProtocol,
            {{QStringLiteral("sender-mixed@example.net"), {QString::fromLatin1(testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint())}}},
        }});

        const auto result = resolver.resolve();

        QVERIFY(result.flags & KeyResolverCore::Error);
    }

    void test_reports_failure_if_mixed_protocols_are_not_allowed_but_required_by_common_overrides()
    {
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/false);
        resolver.setAllowMixedProtocols(false);
        resolver.setRecipients({u"sender-mixed@example.net"_s});
        resolver.setOverrideKeys({{
            UnknownProtocol,
            {{QStringLiteral("sender-mixed@example.net"),
              {
                  QString::fromLatin1(testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint()),
                  QString::fromLatin1(testKey("prefer-smime@example.net", CMS).primaryFingerprint()),
              }}},
        }});

        const auto result = resolver.resolve();

        QVERIFY(result.flags & KeyResolverCore::Error);
    }

    void test_groups__openpgp_only_mode__ignores_non_openpgp_only_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("group@example.net",
                        {
                            testKey("sender-openpgp@example.net", OpenPGP),
                            testKey("sender-smime@example.net", CMS),
                        }),
            createGroup("group@example.net",
                        {
                            testKey("prefer-smime@example.net", CMS),
                        }),
            createGroup("group@example.net",
                        {
                            testKey("prefer-openpgp@example.net", OpenPGP),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/false, OpenPGP);
        resolver.setRecipients({u"group@example.net"_s});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.encryptionKeys.value(u"group@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"group@example.net"_s)[0].primaryFingerprint(),
                 testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint());
    }

    void test_groups__smime_only_mode__ignores_non_smime_only_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("group@example.net",
                        {
                            testKey("sender-openpgp@example.net", OpenPGP),
                            testKey("sender-smime@example.net", CMS),
                        }),
            createGroup("group@example.net",
                        {
                            testKey("prefer-smime@example.net", CMS),
                        }),
            createGroup("group@example.net",
                        {
                            testKey("prefer-openpgp@example.net", OpenPGP),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/false, CMS);
        resolver.setRecipients({u"group@example.net"_s});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.encryptionKeys.value(u"group@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"group@example.net"_s)[0].primaryFingerprint(),
                 testKey("prefer-smime@example.net", CMS).primaryFingerprint());
    }

    void test_groups__single_protocol_mode__ignores_mixed_protocol_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-mixed@example.net",
                        {
                            testKey("sender-openpgp@example.net", OpenPGP),
                            testKey("sender-smime@example.net", CMS),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/false);
        resolver.setAllowMixedProtocols(false);
        resolver.setRecipients({u"sender-mixed@example.net"_s});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-mixed@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-mixed@example.net"_s)[0].primaryFingerprint(),
                 testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
    }

    void test_groups__mixed_mode__single_protocol_groups_are_preferred_over_mixed_protocol_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("group@example.net",
                        {
                            testKey("sender-openpgp@example.net", OpenPGP),
                            testKey("sender-smime@example.net", CMS),
                        }),
            createGroup("group@example.net",
                        {
                            testKey("prefer-smime@example.net", CMS),
                        }),
            createGroup("group@example.net",
                        {
                            testKey("prefer-openpgp@example.net", OpenPGP),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/false);
        resolver.setRecipients({u"group@example.net"_s});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.encryptionKeys.value(u"group@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"group@example.net"_s)[0].primaryFingerprint(),
                 testKey("prefer-openpgp@example.net", OpenPGP).primaryFingerprint());
    }

    void test_groups__mixed_mode__openpgp_only_group_preferred_over_mixed_protocol_group()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("group@example.net",
                        {
                            testKey("sender-openpgp@example.net", OpenPGP),
                            testKey("sender-smime@example.net", CMS),
                        }),
            createGroup("group@example.net",
                        {
                            testKey("sender-openpgp@example.net", OpenPGP),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/false);
        resolver.setRecipients({u"group@example.net"_s});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.encryptionKeys.value(u"group@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"group@example.net"_s)[0].primaryFingerprint(),
                 testKey("sender-openpgp@example.net", OpenPGP).primaryFingerprint());
    }

    void test_groups__mixed_mode__smime_only_group_preferred_over_mixed_protocol_group()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("group@example.net",
                        {
                            testKey("sender-openpgp@example.net", OpenPGP),
                            testKey("sender-smime@example.net", CMS),
                        }),
            createGroup("group@example.net",
                        {
                            testKey("sender-smime@example.net", CMS),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/false);
        resolver.setRecipients({u"group@example.net"_s});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.encryptionKeys.value(u"group@example.net"_s).size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"group@example.net"_s)[0].primaryFingerprint(),
                 testKey("sender-smime@example.net", CMS).primaryFingerprint());
    }

    void test_groups__mixed_mode__mixed_protocol_groups_are_used()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-mixed@example.net",
                        {
                            testKey("sender-openpgp@example.net", OpenPGP),
                            testKey("sender-smime@example.net", CMS),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/false);
        resolver.setRecipients({u"sender-mixed@example.net"_s});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::MixedProtocols);
        QCOMPARE(result.solution.protocol, UnknownProtocol);
        QCOMPARE(result.solution.encryptionKeys.value(u"sender-mixed@example.net"_s).size(), 2);
    }

    void test_reports_unresolved_addresses_if_both_protocols_are_allowed_but_no_signing_keys_are_found_for_an_address()
    {
        KeyResolverCore resolver(/*encrypt=*/false, /*sign=*/true);
        resolver.setSender(QStringLiteral("unknown@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::SomeUnresolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 0);
    }

    void test_reports_unresolved_addresses_if_openpgp_is_requested_and_no_openpgp_signing_keys_are_found_for_an_address()
    {
        KeyResolverCore resolver(/*encrypt=*/false, /*sign=*/true, OpenPGP);
        resolver.setSender(QStringLiteral("sender-smime@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::SomeUnresolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 0);
    }

    void test_reports_unresolved_addresses_if_smime_is_requested_and_no_smime_signing_keys_are_found_for_an_address()
    {
        KeyResolverCore resolver(/*encrypt=*/false, /*sign=*/true, CMS);
        resolver.setSender(QStringLiteral("sender-openpgp@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::SomeUnresolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.signingKeys.size(), 0);
    }

    void test_reports_unresolved_addresses_if_both_protocols_are_needed_but_no_signing_keys_are_found_for_smime()
    {
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/true);
        resolver.setSender(QStringLiteral("sender-openpgp@example.net"));
        resolver.setRecipients({u"smime-only@example.net"_s});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::SomeUnresolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::MixedProtocols);
        QCOMPARE(result.solution.protocol, UnknownProtocol);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-openpgp@example.net", OpenPGP).primaryFingerprint());
    }

    void test_reports_unresolved_addresses_if_both_protocols_are_needed_but_no_signing_keys_are_found_for_openpgp()
    {
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/true);
        resolver.setSender(QStringLiteral("sender-smime@example.net"));
        resolver.setRecipients({u"openpgp-only@example.net"_s});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::SomeUnresolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::MixedProtocols);
        QCOMPARE(result.solution.protocol, UnknownProtocol);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-smime@example.net", CMS).primaryFingerprint());
    }

    void test_groups_for_signing_key__openpgp_only_mode__prefers_groups_over_keys()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-mixed@example.net",
                        {
                            testKey("sender-openpgp@example.net", OpenPGP),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/false, /*sign=*/true, OpenPGP);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-openpgp@example.net", OpenPGP).primaryFingerprint());
    }

    void test_groups_for_signing_key__openpgp_only_mode__prefers_single_protocol_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-alias@example.net",
                        {
                            testKey("sender-mixed@example.net", OpenPGP),
                            testKey("sender-mixed@example.net", CMS),
                        }),
            createGroup("sender-alias@example.net",
                        {
                            testKey("sender-openpgp@example.net", OpenPGP),
                        }),
            createGroup("sender-alias@example.net",
                        {
                            testKey("sender-smime@example.net", CMS),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/false, /*sign=*/true, OpenPGP);
        resolver.setSender(QStringLiteral("sender-alias@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-openpgp@example.net", OpenPGP).primaryFingerprint());
    }

    void test_groups_for_signing_key__openpgp_only_mode__takes_key_of_mixed_protocol_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-alias@example.net",
                        {
                            testKey("sender-mixed@example.net", OpenPGP),
                            testKey("sender-mixed@example.net", CMS),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/false, /*sign=*/true, OpenPGP);
        resolver.setSender(QStringLiteral("sender-alias@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
    }

    void test_groups_for_signing_key__smime_only_mode__prefers_groups_over_keys()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-mixed@example.net",
                        {
                            testKey("sender-smime@example.net", CMS),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/false, /*sign=*/true, CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-smime@example.net", CMS).primaryFingerprint());
    }

    void test_groups_for_signing_key__smime_only_mode__prefers_single_protocol_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-alias@example.net",
                        {
                            testKey("sender-mixed@example.net", OpenPGP),
                            testKey("sender-mixed@example.net", CMS),
                        }),
            createGroup("sender-alias@example.net",
                        {
                            testKey("sender-openpgp@example.net", OpenPGP),
                        }),
            createGroup("sender-alias@example.net",
                        {
                            testKey("sender-smime@example.net", CMS),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/false, /*sign=*/true, CMS);
        resolver.setSender(QStringLiteral("sender-alias@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-smime@example.net", CMS).primaryFingerprint());
    }

    void test_groups_for_signing_key__smime_only_mode__takes_key_of_mixed_protocol_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-alias@example.net",
                        {
                            testKey("sender-mixed@example.net", OpenPGP),
                            testKey("sender-mixed@example.net", CMS),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/false, /*sign=*/true, CMS);
        resolver.setSender(QStringLiteral("sender-alias@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-mixed@example.net", CMS).primaryFingerprint());
    }

    void test_groups_for_signing_key__single_protocol_mode__prefers_groups_over_keys()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-mixed@example.net",
                        {
                            testKey("sender-openpgp@example.net", OpenPGP),
                            testKey("sender-smime@example.net", CMS),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/false, /*sign=*/true);
        resolver.setAllowMixedProtocols(false);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-openpgp@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.alternative.signingKeys.size(), 1);
        QCOMPARE(result.alternative.signingKeys[0].primaryFingerprint(), testKey("sender-smime@example.net", CMS).primaryFingerprint());
    }

    void test_groups_for_signing_key__single_protocol_mode__prefers_single_protocol_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-alias@example.net",
                        {
                            testKey("sender-mixed@example.net", OpenPGP),
                            testKey("sender-mixed@example.net", CMS),
                        }),
            createGroup("sender-alias@example.net",
                        {
                            testKey("sender-openpgp@example.net", OpenPGP),
                        }),
            createGroup("sender-alias@example.net",
                        {
                            testKey("sender-smime@example.net", CMS),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/false, /*sign=*/true);
        resolver.setAllowMixedProtocols(false);
        resolver.setSender(QStringLiteral("sender-alias@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-openpgp@example.net", OpenPGP).primaryFingerprint());
        QCOMPARE(result.alternative.signingKeys.size(), 1);
        QCOMPARE(result.alternative.signingKeys[0].primaryFingerprint(), testKey("sender-smime@example.net", CMS).primaryFingerprint());
    }

    void test_groups_for_signing_key__mixed_mode__prefers_groups_over_keys()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-mixed@example.net",
                        {
                            testKey("sender-openpgp@example.net", OpenPGP),
                            testKey("sender-smime@example.net", CMS),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/false, /*sign=*/true);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-openpgp@example.net", OpenPGP).primaryFingerprint());
    }

    void test_groups_for_signing_key__mixed_mode_with_smime_preferred__prefers_groups_over_keys()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-mixed@example.net",
                        {
                            testKey("sender-openpgp@example.net", OpenPGP),
                            testKey("sender-smime@example.net", CMS),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/false, /*sign=*/true);
        resolver.setPreferredProtocol(CMS);
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-smime@example.net", CMS).primaryFingerprint());
    }

    void test_groups_for_signing_key__mixed_mode__prefers_single_protocol_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-alias@example.net",
                        {
                            testKey("sender-mixed@example.net", OpenPGP),
                            testKey("sender-mixed@example.net", CMS),
                        }),
            createGroup("sender-alias@example.net",
                        {
                            testKey("sender-openpgp@example.net", OpenPGP),
                        }),
            createGroup("sender-alias@example.net",
                        {
                            testKey("sender-smime@example.net", CMS),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/false, /*sign=*/true);
        resolver.setSender(QStringLiteral("sender-alias@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-openpgp@example.net", OpenPGP).primaryFingerprint());
    }

    void test_groups_for_signing_key__mixed_mode_with_smime_preferred__prefers_single_protocol_groups()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("sender-alias@example.net",
                        {
                            testKey("sender-mixed@example.net", OpenPGP),
                            testKey("sender-mixed@example.net", CMS),
                        }),
            createGroup("sender-alias@example.net",
                        {
                            testKey("sender-openpgp@example.net", OpenPGP),
                        }),
            createGroup("sender-alias@example.net",
                        {
                            testKey("sender-smime@example.net", CMS),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/false, /*sign=*/true);
        resolver.setPreferredProtocol(CMS);
        resolver.setSender(QStringLiteral("sender-alias@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-smime@example.net", CMS).primaryFingerprint());
    }

    void test_groups__group_with_marginally_valid_key_is_accepted_by_default()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("group@example.net",
                        {
                            testKey("prefer-openpgp@example.net", OpenPGP),
                            testKey("prefer-smime@example.net", OpenPGP),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/false);
        resolver.setPreferredProtocol(OpenPGP);
        resolver.setRecipients({u"group@example.net"_s});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.encryptionKeys.size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"group@example.net"_s).size(), 2);
    }

    void test_groups__group_with_marginally_valid_key_is_ignored_if_full_validity_required()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("group@example.net",
                        {
                            testKey("prefer-openpgp@example.net", OpenPGP),
                            testKey("prefer-smime@example.net", OpenPGP),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/false);
        resolver.setMinimumValidity(UserID::Full);
        resolver.setPreferredProtocol(OpenPGP);
        resolver.setRecipients({u"group@example.net"_s});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::SomeUnresolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.encryptionKeys.size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"group@example.net"_s).size(), 0);
    }

    void test_groups__group_with_marginally_valid_key_is_ignored_in_de_vs_mode()
    {
        const std::vector<KeyGroup> groups = {
            createGroup("group@example.net",
                        {
                            testKey("prefer-openpgp@example.net", OpenPGP),
                            testKey("prefer-smime@example.net", OpenPGP),
                        }),
        };
        KeyCache::mutableInstance()->setGroups(groups);
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/false);
        resolver.setPreferredProtocol(OpenPGP);
        resolver.setRecipients({u"group@example.net"_s});

        Tests::FakeCryptoConfigStringValue fakeCompliance{"gpg", "compliance", QStringLiteral("de-vs")};
        Tests::FakeCryptoConfigIntValue fakeDeVsCompliance{"gpg", "compliance_de_vs", 1};
        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::SomeUnresolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.encryptionKeys.size(), 1);
        QCOMPARE(result.solution.encryptionKeys.value(u"group@example.net"_s).size(), 0);
    }

    void test_sender_is_set__encrypt_only_mode()
    {
        KeyResolverCore resolver(/*encrypt=*/true, /*sign=*/false);
        resolver.setRecipients({u"prefer-openpgp@example.net"_s, u"prefer-smime@example.net"_s});
        resolver.setSender(QStringLiteral("sender-mixed@example.net"));

        const auto result = resolver.resolve();

        QCOMPARE(resolver.normalizedSender(), QLatin1StringView{"sender-mixed@example.net"});
    }

    void test_setSigningKeys_is_preferred()
    {
        KeyResolverCore resolver(/*encrypt=*/false, /*sign=*/true);
        resolver.setSender(QStringLiteral("sender-openpgp@example.net"));
        resolver.setSigningKeys({QString::fromLatin1(testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint()),
                                 QString::fromLatin1(testKey("sender-mixed@example.net", CMS).primaryFingerprint())});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
    }

    void test_setSigningKeys_is_preferred_smime()
    {
        KeyResolverCore resolver(/*encrypt=*/false, /*sign=*/true);
        resolver.setSender(QStringLiteral("sender-smime@example.net"));
        resolver.setSigningKeys({QString::fromLatin1(testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint()),
                                 QString::fromLatin1(testKey("sender-mixed@example.net", CMS).primaryFingerprint())});
        resolver.setPreferredProtocol(CMS);

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-mixed@example.net", CMS).primaryFingerprint());
    }

    void test_setSigningKeys_is_preferred_only_openpgp()
    {
        KeyResolverCore resolver(/*encrypt=*/false, /*sign=*/true, OpenPGP);
        resolver.setSender(QStringLiteral("sender-openpgp@example.net"));
        resolver.setSigningKeys({QString::fromLatin1(testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint())});

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::OpenPGPOnly);
        QCOMPARE(result.solution.protocol, OpenPGP);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-mixed@example.net", OpenPGP).primaryFingerprint());
    }

    void test_setSigningKeys_is_preferred_only_smime()
    {
        KeyResolverCore resolver(/*encrypt=*/false, /*sign=*/true, CMS);
        resolver.setSender(QStringLiteral("sender-smime@example.net"));
        resolver.setSigningKeys({QString::fromLatin1(testKey("sender-mixed@example.net", CMS).primaryFingerprint())});
        resolver.setPreferredProtocol(CMS);

        const auto result = resolver.resolve();

        QCOMPARE(result.flags & KeyResolverCore::ResolvedMask, KeyResolverCore::AllResolved);
        QCOMPARE(result.flags & KeyResolverCore::ProtocolsMask, KeyResolverCore::CMSOnly);
        QCOMPARE(result.solution.protocol, CMS);
        QCOMPARE(result.solution.signingKeys.size(), 1);
        QCOMPARE(result.solution.signingKeys[0].primaryFingerprint(), testKey("sender-mixed@example.net", CMS).primaryFingerprint());
    }

private:
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
    bool mNeedToCreateSocketDir = false;
    QSharedPointer<QTemporaryDir> mGnupgHome;
    std::shared_ptr<const KeyCache> mKeyCache;
};

QTEST_MAIN(KeyResolverCoreTest)
#include "keyresolvercoretest.moc"
