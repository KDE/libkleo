/*
    autotests/newkeyapprovaldialogtest.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/KeySelectionCombo>
#include <Libkleo/NewKeyApprovalDialog>
#include <Libkleo/Predicates>
#include <Libkleo/Test>

#include <QCheckBox>
#include <QGroupBox>
#include <QLabel>
#include <QObject>
#include <QPushButton>
#include <QRadioButton>
#include <QSignalSpy>
#include <QTest>

#include <gpgme++/key.h>

#include <gpgme.h>

#include <memory>
#include <set>

using namespace Kleo;

namespace QTest
{
template <>
inline char *toString(const bool &t)
{
    return t ? qstrdup("true") : qstrdup("false");
}

template <>
inline bool qCompare(bool const &t1, bool const &t2, const char *actual, const char *expected,
                     const char *file, int line)
{
    return compare_helper(t1 == t2, "Compared values are not the same",
                          toString(t1), toString(t2), actual, expected, file, line);
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

// copied from NewKeyApprovalDialog::Private
enum Action {
    Unset,
    GenerateKey,
    IgnoreKey,
};


auto mapValidity(GpgME::UserID::Validity validity)
{
    switch (validity) {
    default:
    case GpgME::UserID::Unknown: return GPGME_VALIDITY_UNKNOWN;
    case GpgME::UserID::Undefined: return GPGME_VALIDITY_UNDEFINED;
    case GpgME::UserID::Never: return GPGME_VALIDITY_NEVER;
    case GpgME::UserID::Marginal: return GPGME_VALIDITY_MARGINAL;
    case GpgME::UserID::Full: return GPGME_VALIDITY_FULL;
    case GpgME::UserID::Ultimate: return GPGME_VALIDITY_ULTIMATE;
    }
}

GpgME::Key createTestKey(const char *uid, GpgME::Protocol protocol = GpgME::UnknownProtocol, KeyUsage usage = KeyUsage::AnyUsage,
                         GpgME::UserID::Validity validity = GpgME::UserID::Full)
{
    static int count = 0;
    count++;

    gpgme_key_t key;
    gpgme_key_from_uid(&key, uid);
    Q_ASSERT(key);
    Q_ASSERT(key->uids);
    if (protocol != GpgME::UnknownProtocol) {
        key->protocol = protocol == GpgME::OpenPGP ? GPGME_PROTOCOL_OpenPGP : GPGME_PROTOCOL_CMS;
    }
    const QByteArray fingerprint = QByteArray::number(count, 16).rightJustified(40, '0');
    key->fpr = strdup(fingerprint.constData());
    key->revoked = 0;
    key->expired = 0;
    key->disabled = 0;
    key->can_encrypt = int(usage == KeyUsage::AnyUsage || usage == KeyUsage::Encrypt);
    key->can_sign = int(usage == KeyUsage::AnyUsage || usage == KeyUsage::Sign);
    key->secret = 1;
    key->uids->validity = mapValidity(validity);

    return GpgME::Key(key, false);
}

auto testKey(const char *address, GpgME::Protocol protocol = GpgME::UnknownProtocol)
{
    const auto email = GpgME::UserID::addrSpecFromString(address);
    const auto keys = KeyCache::instance()->findByEMailAddress(email);
    for (const auto &key: keys) {
        if (protocol == GpgME::UnknownProtocol || key.protocol() == protocol) {
            return key;
        }
    }
    return GpgME::Key();
}

void waitForKeySelectionCombosBeingInitialized(const QDialog *dialog)
{
    QVERIFY(dialog);
    auto combo = dialog->findChild<KeySelectionCombo *>();
    QVERIFY(combo);

    const auto spy = std::make_unique<QSignalSpy>(combo, &KeySelectionCombo::keyListingFinished);
    QVERIFY(spy->isValid());
    QVERIFY(spy->wait(10));
}

template <typename T>
struct Widgets
{
    std::vector<T *> visible;
    std::vector<T *> hidden;
};

template <typename T>
Widgets<T> visibleAndHiddenWidgets(const QList<T *> &widgets)
{
    Widgets<T> result;
    std::partition_copy(std::begin(widgets), std::end(widgets),
                        std::back_inserter(result.visible),
                        std::back_inserter(result.hidden),
                        std::mem_fn(&QWidget::isVisible));
    return result;
}

enum Visibility {
    IsHidden,
    IsVisible
};

enum CheckedState {
    IsUnchecked,
    IsChecked
};

template <typename T>
void verifyProtocolButton(const T *button, Visibility expectedVisibility, CheckedState expectedCheckedState)
{
    QVERIFY(button);
    QCOMPARE(button->isVisible(), expectedVisibility == IsVisible);
    QCOMPARE(button->isChecked(), expectedCheckedState == IsChecked);
}

template <typename T>
void verifyWidgetVisibility(const T *widget, Visibility expectedVisibility)
{
    QVERIFY(widget);
    QCOMPARE(widget->isVisible(), expectedVisibility == IsVisible);
}

template <typename T>
void verifyWidgetsVisibility(const QList<T> &widgets, Visibility expectedVisibility)
{
    for (auto w: widgets) {
        verifyWidgetVisibility(w, expectedVisibility);
    }
}

void verifyProtocolLabels(const QList<QLabel *> &labels, int expectedNumber, Visibility expectedVisibility)
{
    QCOMPARE(labels.size(), expectedNumber);
    verifyWidgetsVisibility(labels, expectedVisibility);
}

bool listsOfKeysAreEqual(const std::vector<GpgME::Key> &l1, const std::vector<GpgME::Key> &l2)
{
    return std::equal(std::begin(l1), std::end(l1),
                      std::begin(l2), std::end(l2),
                      ByFingerprint<std::equal_to>());
}

void verifySolution(const KeyResolver::Solution &actual, const KeyResolver::Solution &expected)
{
    QCOMPARE(actual.protocol, expected.protocol);

    QVERIFY(listsOfKeysAreEqual(actual.signingKeys, expected.signingKeys));

    QVERIFY(std::equal(actual.encryptionKeys.constKeyValueBegin(), actual.encryptionKeys.constKeyValueEnd(),
                       expected.encryptionKeys.constKeyValueBegin(), expected.encryptionKeys.constKeyValueEnd(),
                       [] (const auto& kv1, const auto& kv2) {
                           return kv1.first == kv2.first && listsOfKeysAreEqual(kv1.second, kv2.second);
                       }));
}

void switchKeySelectionCombosFromGenerateKeyToIgnoreKey(const QList<KeySelectionCombo *> &combos)
{
    for (auto combo: combos) {
        if (combo->currentData(Qt::UserRole).toInt() == GenerateKey) {
            const auto ignoreIndex = combo->findData(IgnoreKey);
            QVERIFY(ignoreIndex != -1);
            combo->setCurrentIndex(ignoreIndex);
        }
    }
}

}

class NewKeyApprovalDialogTest: public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void init()
    {
        // hold a reference to the key cache to avoid rebuilding while the test is running
        mKeyCache = KeyCache::instance();

        KeyCache::mutableInstance()->setKeys({
            createTestKey("sender@example.net", GpgME::OpenPGP, KeyUsage::AnyUsage),
            createTestKey("sender@example.net", GpgME::CMS, KeyUsage::AnyUsage),
            createTestKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP, KeyUsage::Encrypt),
            createTestKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS, KeyUsage::Encrypt),
            createTestKey("Marginal Validity <marginal-openpgp@example.net>", GpgME::OpenPGP, KeyUsage::Encrypt, GpgME::UserID::Marginal),
        });
    }

    void cleanup()
    {
        // verify that nobody else holds a reference to the key cache
        QVERIFY(mKeyCache.use_count() == 1);
        mKeyCache.reset();
    }

    void test__verify_test_keys()
    {
        QVERIFY(!testKey("sender@example.net", GpgME::OpenPGP).isNull());
        QVERIFY(!testKey("sender@example.net", GpgME::CMS).isNull());
        QVERIFY(!testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP).isNull());
        QVERIFY(!testKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS).isNull());
        QVERIFY(!testKey("Marginal Validity <marginal-openpgp@example.net>", GpgME::OpenPGP).isNull());
    }

    void test__both_protocols_allowed__mixed_not_allowed__openpgp_preferred()
    {
        const GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        const bool allowMixed = false;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::OpenPGP,
            {testKey("sender@example.net", GpgME::OpenPGP)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("prefer-smime@example.net"), {}},
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::OpenPGP)}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {
            GpgME::CMS,
            {testKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {}},
                {QStringLiteral("prefer-smime@example.net"), {testKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::CMS)}}
            }
        };

        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();

        verifyProtocolButton(dialog->findChild<QRadioButton *>(QStringLiteral("openpgp button")), IsVisible, IsChecked);
        verifyProtocolButton(dialog->findChild<QRadioButton *>(QStringLiteral("smime button")), IsVisible, IsUnchecked);
        const auto signingKeyWidgets = visibleAndHiddenWidgets(dialog->findChildren<KeySelectionCombo *>(QStringLiteral("signing key")));
        QCOMPARE(signingKeyWidgets.visible.size(), 1);
        QCOMPARE(signingKeyWidgets.hidden.size(), 1);
        QCOMPARE(signingKeyWidgets.visible[0]->defaultKey(GpgME::OpenPGP),
                 preferredSolution.signingKeys[0].primaryFingerprint());
        QCOMPARE(signingKeyWidgets.hidden[0]->defaultKey(GpgME::CMS),
                 alternativeSolution.signingKeys[0].primaryFingerprint());

        const auto encryptionKeyWidgets = visibleAndHiddenWidgets(dialog->findChildren<KeySelectionCombo *>(QStringLiteral("encryption key")));
        QCOMPARE(encryptionKeyWidgets.visible.size(), 3);
        QCOMPARE(encryptionKeyWidgets.hidden.size(), 3);

        // encryption key widgets for sender come first (visible for OpenPGP, hidden for S/MIME)
        QCOMPARE(encryptionKeyWidgets.visible[0]->property("address").toString(), sender);
        QCOMPARE(encryptionKeyWidgets.visible[0]->defaultKey(GpgME::OpenPGP),
                 preferredSolution.encryptionKeys.value(sender)[0].primaryFingerprint());
        QCOMPARE(encryptionKeyWidgets.hidden[0]->property("address").toString(), sender);
        QCOMPARE(encryptionKeyWidgets.hidden[0]->defaultKey(GpgME::CMS),
                 alternativeSolution.encryptionKeys.value(sender)[0].primaryFingerprint());

        // encryption key widgets for other recipients follow (visible for OpenPGP, hidden for S/MIME)
        QCOMPARE(encryptionKeyWidgets.visible[1]->property("address").toString(), "prefer-openpgp@example.net");
        QCOMPARE(encryptionKeyWidgets.visible[1]->defaultKey(GpgME::OpenPGP),
                 preferredSolution.encryptionKeys.value("prefer-openpgp@example.net")[0].primaryFingerprint());
        QCOMPARE(encryptionKeyWidgets.hidden[1]->property("address").toString(), "prefer-openpgp@example.net");
        QVERIFY(encryptionKeyWidgets.hidden[1]->defaultKey(GpgME::CMS).isEmpty());
        QCOMPARE(encryptionKeyWidgets.visible[2]->property("address").toString(), "prefer-smime@example.net");
        QVERIFY(encryptionKeyWidgets.visible[2]->defaultKey(GpgME::OpenPGP).isEmpty());
        QCOMPARE(encryptionKeyWidgets.hidden[2]->property("address").toString(), "prefer-smime@example.net");
        QCOMPARE(encryptionKeyWidgets.hidden[2]->defaultKey(GpgME::CMS),
                 alternativeSolution.encryptionKeys.value("prefer-smime@example.net")[0].primaryFingerprint());
    }

    void test__both_protocols_allowed__mixed_not_allowed__smime_preferred()
    {
        const GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        const bool allowMixed = false;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::CMS,
            {testKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {}},
                {QStringLiteral("prefer-smime@example.net"), {testKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::CMS)}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {
            GpgME::OpenPGP,
            {testKey("sender@example.net", GpgME::OpenPGP)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("prefer-smime@example.net"), {}},
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::OpenPGP)}}
            }
        };

        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();

        verifyProtocolButton(dialog->findChild<QRadioButton *>(QStringLiteral("openpgp button")), IsVisible, IsUnchecked);
        verifyProtocolButton(dialog->findChild<QRadioButton *>(QStringLiteral("smime button")), IsVisible, IsChecked);
        const auto signingKeyWidgets = visibleAndHiddenWidgets(dialog->findChildren<KeySelectionCombo *>(QStringLiteral("signing key")));
        QCOMPARE(signingKeyWidgets.visible.size(), 1);
        QCOMPARE(signingKeyWidgets.hidden.size(), 1);
        QCOMPARE(signingKeyWidgets.visible[0]->defaultKey(GpgME::CMS),
                 preferredSolution.signingKeys[0].primaryFingerprint());
        QCOMPARE(signingKeyWidgets.hidden[0]->defaultKey(GpgME::OpenPGP),
                 alternativeSolution.signingKeys[0].primaryFingerprint());

        const auto encryptionKeyWidgets = visibleAndHiddenWidgets(dialog->findChildren<KeySelectionCombo *>(QStringLiteral("encryption key")));
        QCOMPARE(encryptionKeyWidgets.visible.size(), 3);
        QCOMPARE(encryptionKeyWidgets.hidden.size(), 3);

        // encryption key widgets for sender come first (visible for S/MIME, hidden for OpenPGP)
        QCOMPARE(encryptionKeyWidgets.visible[0]->property("address").toString(), sender);
        QCOMPARE(encryptionKeyWidgets.visible[0]->defaultKey(GpgME::CMS),
                 preferredSolution.encryptionKeys.value(sender)[0].primaryFingerprint());
        QCOMPARE(encryptionKeyWidgets.hidden[0]->property("address").toString(), sender);
        QCOMPARE(encryptionKeyWidgets.hidden[0]->defaultKey(GpgME::OpenPGP),
                 alternativeSolution.encryptionKeys.value(sender)[0].primaryFingerprint());

        // encryption key widgets for other recipients follow (visible for OpenPGP, hidden for S/MIME)
        QCOMPARE(encryptionKeyWidgets.visible[1]->property("address").toString(), "prefer-openpgp@example.net");
        QVERIFY(encryptionKeyWidgets.visible[1]->defaultKey(GpgME::CMS).isEmpty());
        QCOMPARE(encryptionKeyWidgets.hidden[1]->property("address").toString(), "prefer-openpgp@example.net");
        QCOMPARE(encryptionKeyWidgets.hidden[1]->defaultKey(GpgME::OpenPGP),
                 alternativeSolution.encryptionKeys.value("prefer-openpgp@example.net")[0].primaryFingerprint());
        QCOMPARE(encryptionKeyWidgets.visible[2]->property("address").toString(), "prefer-smime@example.net");
        QCOMPARE(encryptionKeyWidgets.visible[2]->defaultKey(GpgME::CMS),
                 preferredSolution.encryptionKeys.value("prefer-smime@example.net")[0].primaryFingerprint());
        QCOMPARE(encryptionKeyWidgets.hidden[2]->property("address").toString(), "prefer-smime@example.net");
        QVERIFY(encryptionKeyWidgets.hidden[2]->defaultKey(GpgME::OpenPGP).isEmpty());
    }

    void test__openpgp_only()
    {
        const GpgME::Protocol forcedProtocol = GpgME::OpenPGP;
        const bool allowMixed = false;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::OpenPGP,
            {testKey("sender@example.net", GpgME::OpenPGP)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("prefer-smime@example.net"), {}},
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::OpenPGP)}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {};

        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();

        verifyProtocolButton(dialog->findChild<QRadioButton *>(QStringLiteral("openpgp button")), IsHidden, IsChecked);
        verifyProtocolButton(dialog->findChild<QRadioButton *>(QStringLiteral("smime button")), IsHidden, IsUnchecked);
        const auto signingKeyWidgets = visibleAndHiddenWidgets(dialog->findChildren<KeySelectionCombo *>(QStringLiteral("signing key")));
        QCOMPARE(signingKeyWidgets.visible.size(), 1);
        QCOMPARE(signingKeyWidgets.hidden.size(), 0);
        QCOMPARE(signingKeyWidgets.visible[0]->defaultKey(GpgME::OpenPGP),
                 preferredSolution.signingKeys[0].primaryFingerprint());

        const auto encryptionKeyWidgets = visibleAndHiddenWidgets(dialog->findChildren<KeySelectionCombo *>(QStringLiteral("encryption key")));
        QCOMPARE(encryptionKeyWidgets.visible.size(), 3);
        QCOMPARE(encryptionKeyWidgets.hidden.size(), 0);

        // encryption key widget for sender comes first
        QCOMPARE(encryptionKeyWidgets.visible[0]->property("address").toString(), sender);
        QCOMPARE(encryptionKeyWidgets.visible[0]->defaultKey(GpgME::OpenPGP),
                 preferredSolution.encryptionKeys.value(sender)[0].primaryFingerprint());

        // encryption key widgets for other recipients follow
        QCOMPARE(encryptionKeyWidgets.visible[1]->property("address").toString(), "prefer-openpgp@example.net");
        QCOMPARE(encryptionKeyWidgets.visible[1]->defaultKey(GpgME::OpenPGP),
                 preferredSolution.encryptionKeys.value("prefer-openpgp@example.net")[0].primaryFingerprint());
        QCOMPARE(encryptionKeyWidgets.visible[2]->property("address").toString(), "prefer-smime@example.net");
        QVERIFY(encryptionKeyWidgets.visible[2]->defaultKey(GpgME::OpenPGP).isEmpty());
    }

    void test__smime_only()
    {
        const GpgME::Protocol forcedProtocol = GpgME::CMS;
        const bool allowMixed = false;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::CMS,
            {testKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {}},
                {QStringLiteral("prefer-smime@example.net"), {testKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::CMS)}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {};

        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();

        verifyProtocolButton(dialog->findChild<QRadioButton *>(QStringLiteral("openpgp button")), IsHidden, IsUnchecked);
        verifyProtocolButton(dialog->findChild<QRadioButton *>(QStringLiteral("smime button")), IsHidden, IsChecked);
        const auto signingKeyWidgets = visibleAndHiddenWidgets(dialog->findChildren<KeySelectionCombo *>(QStringLiteral("signing key")));
        QCOMPARE(signingKeyWidgets.visible.size(), 1);
        QCOMPARE(signingKeyWidgets.hidden.size(), 0);
        QCOMPARE(signingKeyWidgets.visible[0]->defaultKey(GpgME::CMS),
                 preferredSolution.signingKeys[0].primaryFingerprint());

        const auto encryptionKeyWidgets = visibleAndHiddenWidgets(dialog->findChildren<KeySelectionCombo *>(QStringLiteral("encryption key")));
        QCOMPARE(encryptionKeyWidgets.visible.size(), 3);
        QCOMPARE(encryptionKeyWidgets.hidden.size(), 0);

        // encryption key widget for sender comes first
        QCOMPARE(encryptionKeyWidgets.visible[0]->property("address").toString(), sender);
        QCOMPARE(encryptionKeyWidgets.visible[0]->defaultKey(GpgME::CMS),
                 preferredSolution.encryptionKeys.value(sender)[0].primaryFingerprint());

        // encryption key widgets for other recipients follow
        QCOMPARE(encryptionKeyWidgets.visible[1]->property("address").toString(), "prefer-openpgp@example.net");
        QVERIFY(encryptionKeyWidgets.visible[1]->defaultKey(GpgME::CMS).isEmpty());
        QCOMPARE(encryptionKeyWidgets.visible[2]->property("address").toString(), "prefer-smime@example.net");
        QCOMPARE(encryptionKeyWidgets.visible[2]->defaultKey(GpgME::CMS),
                 preferredSolution.encryptionKeys.value("prefer-smime@example.net")[0].primaryFingerprint());
    }

    void test__both_protocols_allowed__mixed_allowed()
    {
        const GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        const bool allowMixed = true;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::UnknownProtocol,
            {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("prefer-smime@example.net"), {testKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
                {QStringLiteral("unknown@example.net"), {}},
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {};

        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();

        verifyProtocolButton(dialog->findChild<QCheckBox *>(QStringLiteral("openpgp button")), IsVisible, IsChecked);
        verifyProtocolButton(dialog->findChild<QCheckBox *>(QStringLiteral("smime button")), IsVisible, IsChecked);
        verifyProtocolLabels(dialog->findChildren<QLabel *>(QStringLiteral("protocol label")), 4, IsVisible);
        const auto signingKeyWidgets = visibleAndHiddenWidgets(dialog->findChildren<KeySelectionCombo *>(QStringLiteral("signing key")));
        QCOMPARE(signingKeyWidgets.visible.size(), 2);
        QCOMPARE(signingKeyWidgets.hidden.size(), 0);
        QCOMPARE(signingKeyWidgets.visible[0]->defaultKey(GpgME::OpenPGP),
                 preferredSolution.signingKeys[0].primaryFingerprint());
        QCOMPARE(signingKeyWidgets.visible[1]->defaultKey(GpgME::CMS),
                 preferredSolution.signingKeys[1].primaryFingerprint());

        const auto encryptionKeyWidgets = visibleAndHiddenWidgets(dialog->findChildren<KeySelectionCombo *>(QStringLiteral("encryption key")));
        QCOMPARE(encryptionKeyWidgets.visible.size(), 5);
        QCOMPARE(encryptionKeyWidgets.hidden.size(), 0);

        // encryption key widgets for sender come first
        QCOMPARE(encryptionKeyWidgets.visible[0]->property("address").toString(), sender);
        QCOMPARE(encryptionKeyWidgets.visible[0]->defaultKey(GpgME::OpenPGP),
                 preferredSolution.encryptionKeys.value(sender)[0].primaryFingerprint());
        QCOMPARE(encryptionKeyWidgets.visible[1]->property("address").toString(), sender);
        QCOMPARE(encryptionKeyWidgets.visible[1]->defaultKey(GpgME::CMS),
                 preferredSolution.encryptionKeys.value(sender)[1].primaryFingerprint());

        // encryption key widgets for other recipients follow
        QCOMPARE(encryptionKeyWidgets.visible[2]->property("address").toString(), "prefer-openpgp@example.net");
        QCOMPARE(encryptionKeyWidgets.visible[2]->defaultKey(GpgME::UnknownProtocol),
                 preferredSolution.encryptionKeys.value("prefer-openpgp@example.net")[0].primaryFingerprint());
        QCOMPARE(encryptionKeyWidgets.visible[3]->property("address").toString(), "prefer-smime@example.net");
        QCOMPARE(encryptionKeyWidgets.visible[3]->defaultKey(GpgME::UnknownProtocol),
                 preferredSolution.encryptionKeys.value("prefer-smime@example.net")[0].primaryFingerprint());
        QCOMPARE(encryptionKeyWidgets.visible[4]->property("address").toString(), "unknown@example.net");
        QVERIFY(encryptionKeyWidgets.visible[4]->defaultKey(GpgME::UnknownProtocol).isEmpty());
    }

    void test__both_protocols_allowed__mixed_allowed__openpgp_only_preferred_solution()
    {
        const GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        const bool allowMixed = true;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::OpenPGP,
            {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("unknown@example.net"), {}},
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {};

        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();

        verifyProtocolButton(dialog->findChild<QCheckBox *>(QStringLiteral("openpgp button")), IsVisible, IsChecked);
        verifyProtocolButton(dialog->findChild<QCheckBox *>(QStringLiteral("smime button")), IsVisible, IsUnchecked);
        verifyProtocolLabels(dialog->findChildren<QLabel *>(QStringLiteral("protocol label")), 4, IsHidden);
        const auto signingKeyWidgets = visibleAndHiddenWidgets(dialog->findChildren<KeySelectionCombo *>(QStringLiteral("signing key")));
        QCOMPARE(signingKeyWidgets.visible.size(), 1);
        QCOMPARE(signingKeyWidgets.hidden.size(), 1);
        QCOMPARE(signingKeyWidgets.visible[0]->defaultKey(GpgME::OpenPGP),
                 preferredSolution.signingKeys[0].primaryFingerprint());
        QCOMPARE(signingKeyWidgets.hidden[0]->defaultKey(GpgME::CMS),
                 preferredSolution.signingKeys[1].primaryFingerprint());

        const auto encryptionKeyWidgets = visibleAndHiddenWidgets(dialog->findChildren<KeySelectionCombo *>(QStringLiteral("encryption key")));
        QCOMPARE(encryptionKeyWidgets.visible.size(), 3);
        QCOMPARE(encryptionKeyWidgets.hidden.size(), 1);

        // encryption key widgets for sender come first
        QCOMPARE(encryptionKeyWidgets.visible[0]->property("address").toString(), sender);
        QCOMPARE(encryptionKeyWidgets.visible[0]->defaultKey(GpgME::OpenPGP),
                 preferredSolution.encryptionKeys.value(sender)[0].primaryFingerprint());
        QCOMPARE(encryptionKeyWidgets.hidden[0]->property("address").toString(), sender);
        QCOMPARE(encryptionKeyWidgets.hidden[0]->defaultKey(GpgME::CMS),
                 preferredSolution.encryptionKeys.value(sender)[1].primaryFingerprint());

        // encryption key widgets for other recipients follow
        QCOMPARE(encryptionKeyWidgets.visible[1]->property("address").toString(), "prefer-openpgp@example.net");
        QCOMPARE(encryptionKeyWidgets.visible[1]->defaultKey(GpgME::UnknownProtocol),
                 preferredSolution.encryptionKeys.value("prefer-openpgp@example.net")[0].primaryFingerprint());
        QCOMPARE(encryptionKeyWidgets.visible[2]->property("address").toString(), "unknown@example.net");
        QVERIFY(encryptionKeyWidgets.visible[2]->defaultKey(GpgME::UnknownProtocol).isEmpty());
    }

    void test__both_protocols_allowed__mixed_allowed__smime_only_preferred_solution()
    {
        const GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        const bool allowMixed = true;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::CMS,
            {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("prefer-smime@example.net"), {testKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
                {QStringLiteral("unknown@example.net"), {}},
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {};

        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();

        verifyProtocolButton(dialog->findChild<QCheckBox *>(QStringLiteral("openpgp button")), IsVisible, IsUnchecked);
        verifyProtocolButton(dialog->findChild<QCheckBox *>(QStringLiteral("smime button")), IsVisible, IsChecked);
        verifyProtocolLabels(dialog->findChildren<QLabel *>(QStringLiteral("protocol label")), 4, IsHidden);
        const auto signingKeyWidgets = visibleAndHiddenWidgets(dialog->findChildren<KeySelectionCombo *>(QStringLiteral("signing key")));
        QCOMPARE(signingKeyWidgets.visible.size(), 1);
        QCOMPARE(signingKeyWidgets.hidden.size(), 1);
        QCOMPARE(signingKeyWidgets.visible[0]->defaultKey(GpgME::CMS),
                 preferredSolution.signingKeys[1].primaryFingerprint());
        QCOMPARE(signingKeyWidgets.hidden[0]->defaultKey(GpgME::OpenPGP),
                 preferredSolution.signingKeys[0].primaryFingerprint());

        const auto encryptionKeyWidgets = visibleAndHiddenWidgets(dialog->findChildren<KeySelectionCombo *>(QStringLiteral("encryption key")));
        QCOMPARE(encryptionKeyWidgets.visible.size(), 3);
        QCOMPARE(encryptionKeyWidgets.hidden.size(), 1);

        // encryption key widgets for sender come first
        QCOMPARE(encryptionKeyWidgets.visible[0]->property("address").toString(), sender);
        QCOMPARE(encryptionKeyWidgets.visible[0]->defaultKey(GpgME::CMS),
                 preferredSolution.encryptionKeys.value(sender)[1].primaryFingerprint());
        QCOMPARE(encryptionKeyWidgets.hidden[0]->property("address").toString(), sender);
        QCOMPARE(encryptionKeyWidgets.hidden[0]->defaultKey(GpgME::OpenPGP),
                 preferredSolution.encryptionKeys.value(sender)[0].primaryFingerprint());

        // encryption key widgets for other recipients follow
        QCOMPARE(encryptionKeyWidgets.visible[1]->property("address").toString(), "prefer-smime@example.net");
        QCOMPARE(encryptionKeyWidgets.visible[1]->defaultKey(GpgME::UnknownProtocol),
                 preferredSolution.encryptionKeys.value("prefer-smime@example.net")[0].primaryFingerprint());
        QCOMPARE(encryptionKeyWidgets.visible[2]->property("address").toString(), "unknown@example.net");
        QVERIFY(encryptionKeyWidgets.visible[2]->defaultKey(GpgME::UnknownProtocol).isEmpty());
    }

    void test__both_protocols_allowed__mixed_allowed__no_sender_keys()
    {
        const GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        const bool allowMixed = true;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::UnknownProtocol,
            {},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("prefer-smime@example.net"), {testKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
                {QStringLiteral("unknown@example.net"), {}},
                {QStringLiteral("sender@example.net"), {}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {};

        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();

        const auto signingKeyWidgets = visibleAndHiddenWidgets(dialog->findChildren<KeySelectionCombo *>(QStringLiteral("signing key")));
        QCOMPARE(signingKeyWidgets.visible.size(), 2);
        QCOMPARE(signingKeyWidgets.hidden.size(), 0);

        const auto encryptionKeyWidgets = visibleAndHiddenWidgets(dialog->findChildren<KeySelectionCombo *>(QStringLiteral("encryption key")));
        QCOMPARE(encryptionKeyWidgets.visible.size(), 5);
        QCOMPARE(encryptionKeyWidgets.hidden.size(), 0);

        // encryption key widgets for sender come first
        QCOMPARE(encryptionKeyWidgets.visible[0]->property("address").toString(), sender);
        QCOMPARE(encryptionKeyWidgets.visible[1]->property("address").toString(), sender);

        // encryption key widgets for other recipients follow
        QCOMPARE(encryptionKeyWidgets.visible[2]->property("address").toString(), "prefer-openpgp@example.net");
        QCOMPARE(encryptionKeyWidgets.visible[2]->defaultKey(GpgME::UnknownProtocol),
                 preferredSolution.encryptionKeys.value("prefer-openpgp@example.net")[0].primaryFingerprint());
        QCOMPARE(encryptionKeyWidgets.visible[3]->property("address").toString(), "prefer-smime@example.net");
        QCOMPARE(encryptionKeyWidgets.visible[3]->defaultKey(GpgME::UnknownProtocol),
                 preferredSolution.encryptionKeys.value("prefer-smime@example.net")[0].primaryFingerprint());
        QCOMPARE(encryptionKeyWidgets.visible[4]->property("address").toString(), "unknown@example.net");
        QVERIFY(encryptionKeyWidgets.visible[4]->defaultKey(GpgME::UnknownProtocol).isEmpty());
    }

    void test__both_protocols_allowed__mixed_allowed__encrypt_only()
    {
        const GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        const bool allowMixed = true;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::UnknownProtocol,
            {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("prefer-smime@example.net"), {testKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
                {QStringLiteral("unknown@example.net"), {}},
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {};

        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   false,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();

        const auto signingKeyWidgets = visibleAndHiddenWidgets(dialog->findChildren<KeySelectionCombo *>(QStringLiteral("signing key")));
        QCOMPARE(signingKeyWidgets.visible.size(), 0);
        QCOMPARE(signingKeyWidgets.hidden.size(), 0);

        const auto encryptionKeyWidgets = visibleAndHiddenWidgets(dialog->findChildren<KeySelectionCombo *>(QStringLiteral("encryption key")));
        QCOMPARE(encryptionKeyWidgets.visible.size(), 5);
        QCOMPARE(encryptionKeyWidgets.hidden.size(), 0);
    }

    void test__ok_button_shows_generate_if_generate_is_selected()
    {
        const GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        const bool allowMixed = true;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::OpenPGP,
            {}, // no signing keys to get "Generate key" choice in OpenPGP combo
            {{QStringLiteral("sender@example.net"), {}}} // no encryption keys to get "Generate key" choice in OpenPGP combo
        };
        const KeyResolver::Solution alternativeSolution = {};

        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();
        waitForKeySelectionCombosBeingInitialized(dialog.get());

        const auto okButton = dialog->findChild<QPushButton *>("ok button");
        QVERIFY(okButton);
        QVERIFY(okButton->text() != "Generate");

        {
            // get the first signing key combo which is the OpenPGP one
            const auto signingKeyCombo = dialog->findChild<KeySelectionCombo *>("signing key");
            verifyWidgetVisibility(signingKeyCombo, IsVisible);
            const auto originalIndex = signingKeyCombo->currentIndex();
            const auto generateIndex = signingKeyCombo->findData(GenerateKey);
            QVERIFY(generateIndex != -1);
            signingKeyCombo->setCurrentIndex(generateIndex);
            QCOMPARE(okButton->text(), "Generate");
            signingKeyCombo->setCurrentIndex(originalIndex);
            QVERIFY(okButton->text() != "Generate");
        }
        {
            // get the first encryption key combo which is the OpenPGP one for the sender
            const auto encryptionKeyCombo = dialog->findChild<KeySelectionCombo *>("encryption key");
            verifyWidgetVisibility(encryptionKeyCombo, IsVisible);
            const auto originalIndex = encryptionKeyCombo->currentIndex();
            const auto generateIndex = encryptionKeyCombo->findData(GenerateKey);
            QVERIFY(generateIndex != -1);
            encryptionKeyCombo->setCurrentIndex(generateIndex);
            QCOMPARE(okButton->text(), QStringLiteral("Generate"));
            encryptionKeyCombo->setCurrentIndex(originalIndex);
            QVERIFY(okButton->text() != QStringLiteral("Generate"));
        }
    }

    void test__ok_button_does_not_show_generate_if_generate_is_selected_in_hidden_combos()
    {
        const GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        const bool allowMixed = true;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::CMS, // enables S/MIME as default protocol, hides OpenPGP combos
            {}, // no signing keys to get "Generate key" choice in OpenPGP combo
            {{QStringLiteral("sender@example.net"), {}}} // no encryption keys to get "Generate key" choice in OpenPGP combo
        };
        const KeyResolver::Solution alternativeSolution = {};

        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();
        waitForKeySelectionCombosBeingInitialized(dialog.get());

        const auto okButton = dialog->findChild<QPushButton *>("ok button");
        QVERIFY(okButton);
        QVERIFY(okButton->text() != "Generate");

        {
            // get the first signing key combo which is the OpenPGP one
            const auto signingKeyCombo = dialog->findChild<KeySelectionCombo *>("signing key");
            verifyWidgetVisibility(signingKeyCombo, IsHidden);
            const auto originalIndex = signingKeyCombo->currentIndex();
            const auto generateIndex = signingKeyCombo->findData(GenerateKey);
            QVERIFY(generateIndex != -1);
            signingKeyCombo->setCurrentIndex(generateIndex);
            QVERIFY(okButton->text() != QStringLiteral("Generate"));
            signingKeyCombo->setCurrentIndex(originalIndex);
            QVERIFY(okButton->text() != QStringLiteral("Generate"));
        }
        {
            // get the first encryption key combo which is the OpenPGP one for the sender
            const auto encryptionKeyCombo = dialog->findChild<KeySelectionCombo *>("encryption key");
            verifyWidgetVisibility(encryptionKeyCombo, IsHidden);
            const auto originalIndex = encryptionKeyCombo->currentIndex();
            const auto generateIndex = encryptionKeyCombo->findData(GenerateKey);
            QVERIFY(generateIndex != -1);
            encryptionKeyCombo->setCurrentIndex(generateIndex);
            QVERIFY(okButton->text() != QStringLiteral("Generate"));
            encryptionKeyCombo->setCurrentIndex(originalIndex);
            QVERIFY(okButton->text() != QStringLiteral("Generate"));
        }
    }

    void test__ok_button_is_disabled_if_ignore_is_selected_in_all_visible_encryption_combos()
    {
        const GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        const bool allowMixed = true;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::OpenPGP,
            {}, // no signing keys to get "Generate key" choice in OpenPGP combo
            {{QStringLiteral("sender@example.net"), {}}} // no encryption keys to get "Generate key" choice in OpenPGP combo
        };
        const KeyResolver::Solution alternativeSolution = {};

        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();
        waitForKeySelectionCombosBeingInitialized(dialog.get());

        const auto okButton = dialog->findChild<QPushButton *>(QStringLiteral("ok button"));
        QVERIFY(okButton);
        QVERIFY(okButton->isEnabled());

        const auto encryptionKeyWidgets = visibleAndHiddenWidgets(dialog->findChildren<KeySelectionCombo *>(QStringLiteral("encryption key")));
        for (auto combo: encryptionKeyWidgets.visible) {
            const auto ignoreIndex = combo->findData(IgnoreKey);
            QVERIFY(ignoreIndex != -1);
            combo->setCurrentIndex(ignoreIndex);
        }
        QVERIFY(!okButton->isEnabled());
    }

    void test__vs_de_compliance__all_keys_fully_valid()
    {
        const GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        const bool allowMixed = true;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::UnknownProtocol,
            {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("prefer-smime@example.net"), {testKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {};

        Tests::FakeCryptoConfigStringValue fakeCompliance{"gpg", "compliance", QStringLiteral("de-vs")};
        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();
        waitForKeySelectionCombosBeingInitialized(dialog.get());

        const auto complianceLabel = dialog->findChild<QLabel *>(QStringLiteral("compliance label"));
        verifyWidgetVisibility(complianceLabel, IsVisible);
        QVERIFY(!complianceLabel->text().contains(" not "));
    }

    void test__vs_de_compliance__not_all_keys_fully_valid()
    {
        const GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        const bool allowMixed = true;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::UnknownProtocol,
            {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("marginal-openpgp@example.net"), {testKey("Marginal Validity <marginal-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {};

        Tests::FakeCryptoConfigStringValue fakeCompliance{"gpg", "compliance", QStringLiteral("de-vs")};
        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();
        waitForKeySelectionCombosBeingInitialized(dialog.get());

        const auto complianceLabel = dialog->findChild<QLabel *>(QStringLiteral("compliance label"));
        verifyWidgetVisibility(complianceLabel, IsVisible);
        QVERIFY(complianceLabel->text().contains(" not "));
    }

    void test__vs_de_compliance__null_keys_are_ignored()
    {
        const GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        const bool allowMixed = true;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::UnknownProtocol,
            {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("unknown@example.net"), {}},
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {};

        Tests::FakeCryptoConfigStringValue fakeCompliance{"gpg", "compliance", QStringLiteral("de-vs")};
        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();
        waitForKeySelectionCombosBeingInitialized(dialog.get());

        const auto complianceLabel = dialog->findChild<QLabel *>(QStringLiteral("compliance label"));
        verifyWidgetVisibility(complianceLabel, IsVisible);
        QVERIFY(!complianceLabel->text().contains(" not "));
    }

    void test__sign_and_encrypt_to_self_only()
    {
        const GpgME::Protocol forcedProtocol = GpgME::OpenPGP;
        const bool allowMixed = false;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::OpenPGP,
            {testKey("sender@example.net", GpgME::OpenPGP)},
            {
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::OpenPGP)}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {};

        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();

        QVERIFY(!dialog->findChild<QGroupBox *>(QStringLiteral("encrypt-to-others box")));
    }

    void test__sign_and_encrypt_to_self_and_others()
    {
        const GpgME::Protocol forcedProtocol = GpgME::OpenPGP;
        const bool allowMixed = false;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::OpenPGP,
            {testKey("sender@example.net", GpgME::OpenPGP)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::OpenPGP)}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {};

        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();

        QVERIFY(dialog->findChild<QGroupBox *>(QStringLiteral("encrypt-to-others box")));
    }

    void test__result_does_not_include_null_keys()
    {
        const GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        const bool allowMixed = true;
        const QString sender = QStringLiteral("unknown@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::UnknownProtocol,
            {},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("prefer-smime@example.net"), {testKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
                {QStringLiteral("unknown@example.net"), {}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {};

        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();
        waitForKeySelectionCombosBeingInitialized(dialog.get());
        switchKeySelectionCombosFromGenerateKeyToIgnoreKey(dialog->findChildren<KeySelectionCombo *>());

        const QSignalSpy dialogAcceptedSpy{dialog.get(), &QDialog::accepted};
        QVERIFY(dialogAcceptedSpy.isValid());

        const auto okButton = dialog->findChild<QPushButton *>(QStringLiteral("ok button"));
        QVERIFY(okButton);
        QVERIFY(okButton->isEnabled());
        okButton->click();

        QCOMPARE(dialogAcceptedSpy.count(), 1);
        verifySolution(dialog->result(), {
            GpgME::UnknownProtocol,
            {},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("prefer-smime@example.net"), {testKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
            }
        });
    }

    void test__result_has_keys_for_both_protocols_if_both_are_needed()
    {
        const GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        const bool allowMixed = true;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::UnknownProtocol,
            {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("prefer-smime@example.net"), {testKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {};

        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();
        waitForKeySelectionCombosBeingInitialized(dialog.get());
        switchKeySelectionCombosFromGenerateKeyToIgnoreKey(dialog->findChildren<KeySelectionCombo *>());

        const QSignalSpy dialogAcceptedSpy{dialog.get(), &QDialog::accepted};
        QVERIFY(dialogAcceptedSpy.isValid());

        const auto okButton = dialog->findChild<QPushButton *>(QStringLiteral("ok button"));
        QVERIFY(okButton);
        QVERIFY(okButton->isEnabled());
        okButton->click();

        QCOMPARE(dialogAcceptedSpy.count(), 1);
        verifySolution(dialog->result(), preferredSolution);
    }

    void test__result_has_only_openpgp_keys_if_openpgp_protocol_selected()
    {
        const GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        const bool allowMixed = true;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::UnknownProtocol,
            {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("prefer-smime@example.net"), {testKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {};

        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();
        waitForKeySelectionCombosBeingInitialized(dialog.get());
        switchKeySelectionCombosFromGenerateKeyToIgnoreKey(dialog->findChildren<KeySelectionCombo *>());

        const auto smimeButton = dialog->findChild<QCheckBox *>(QStringLiteral("smime button"));
        QVERIFY(smimeButton);
        smimeButton->click();
        QVERIFY(!smimeButton->isChecked());

        const QSignalSpy dialogAcceptedSpy{dialog.get(), &QDialog::accepted};
        QVERIFY(dialogAcceptedSpy.isValid());

        const auto okButton = dialog->findChild<QPushButton *>(QStringLiteral("ok button"));
        QVERIFY(okButton);
        QVERIFY(okButton->isEnabled());
        okButton->click();

        QCOMPARE(dialogAcceptedSpy.count(), 1);
        verifySolution(dialog->result(), {
            GpgME::OpenPGP,
            {testKey("sender@example.net", GpgME::OpenPGP)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::OpenPGP)}}
            }
        });
    }

    void test__result_has_only_smime_keys_if_smime_protocol_selected()
    {
        const GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        const bool allowMixed = true;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::UnknownProtocol,
            {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {testKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("prefer-smime@example.net"), {testKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::OpenPGP), testKey("sender@example.net", GpgME::CMS)}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {};

        const auto dialog = std::make_unique<NewKeyApprovalDialog>(true,
                                                                   true,
                                                                   sender,
                                                                   preferredSolution,
                                                                   alternativeSolution,
                                                                   allowMixed,
                                                                   forcedProtocol);
        dialog->show();
        waitForKeySelectionCombosBeingInitialized(dialog.get());
        switchKeySelectionCombosFromGenerateKeyToIgnoreKey(dialog->findChildren<KeySelectionCombo *>());

        const auto openPGPButton = dialog->findChild<QCheckBox *>(QStringLiteral("openpgp button"));
        QVERIFY(openPGPButton);
        openPGPButton->click();
        QVERIFY(!openPGPButton->isChecked());

        const QSignalSpy dialogAcceptedSpy{dialog.get(), &QDialog::accepted};
        QVERIFY(dialogAcceptedSpy.isValid());

        const auto okButton = dialog->findChild<QPushButton *>(QStringLiteral("ok button"));
        QVERIFY(okButton);
        QVERIFY(okButton->isEnabled());
        okButton->click();

        QCOMPARE(dialogAcceptedSpy.count(), 1);
        verifySolution(dialog->result(), {
            GpgME::CMS,
            {testKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("prefer-smime@example.net"), {testKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
                {QStringLiteral("sender@example.net"), {testKey("sender@example.net", GpgME::CMS)}}
            }
        });
    }

private:
    std::shared_ptr<const KeyCache> mKeyCache;
};

QTEST_MAIN(NewKeyApprovalDialogTest)
#include "newkeyapprovaldialogtest.moc"
