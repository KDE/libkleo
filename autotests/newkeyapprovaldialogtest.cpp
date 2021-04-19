/*
    autotests/newkeyapprovaldialogtest.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <Libkleo/KeySelectionCombo>
#include <Libkleo/NewKeyApprovalDialog>

#include <QCheckBox>
#include <QLabel>
#include <QObject>
#include <QRadioButton>
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
}

namespace
{

GpgME::Key createTestKey(const char *uid, GpgME::Protocol protocol = GpgME::UnknownProtocol)
{
    static int count = 0;
    count++;

    gpgme_key_t key;
    gpgme_key_from_uid(&key, uid);
    Q_ASSERT(key);
    if (protocol != GpgME::UnknownProtocol) {
        key->protocol = protocol == GpgME::OpenPGP ? GPGME_PROTOCOL_OpenPGP : GPGME_PROTOCOL_CMS;
    }
    const QByteArray fingerprint = QByteArray::number(count, 16).rightJustified(40, '0');
    key->fpr = strdup(fingerprint.constData());

    return GpgME::Key(key, false);
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
void verifyWidgetsVisibility(const QList<T> &widgets, Visibility expectedVisibility)
{
    for (auto w: widgets) {
        QCOMPARE(w->isVisible(), expectedVisibility == IsVisible);
    }
}

void verifyProtocolLabels(const QList<QLabel *> &labels, int expectedNumber, Visibility expectedVisibility)
{
    QCOMPARE(labels.size(), expectedNumber);
    verifyWidgetsVisibility(labels, expectedVisibility);
}

}

class NewKeyApprovalDialogTest: public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void test__both_protocols_allowed__mixed_not_allowed__openpgp_preferred()
    {
        const GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        const bool allowMixed = false;
        const QString sender = QStringLiteral("sender@example.net");
        const KeyResolver::Solution preferredSolution = {
            GpgME::OpenPGP,
            {createTestKey("sender@example.net", GpgME::OpenPGP)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {createTestKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("prefer-smime@example.net"), {}},
                {QStringLiteral("sender@example.net"), {createTestKey("sender@example.net", GpgME::OpenPGP)}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {
            GpgME::CMS,
            {createTestKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {}},
                {QStringLiteral("prefer-smime@example.net"), {createTestKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
                {QStringLiteral("sender@example.net"), {createTestKey("sender@example.net", GpgME::CMS)}}
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

        verifyProtocolButton(dialog->findChild<QRadioButton *>("openpgp button"), IsVisible, IsChecked);
        verifyProtocolButton(dialog->findChild<QRadioButton *>("smime button"), IsVisible, IsUnchecked);
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
            {createTestKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {}},
                {QStringLiteral("prefer-smime@example.net"), {createTestKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
                {QStringLiteral("sender@example.net"), {createTestKey("sender@example.net", GpgME::CMS)}}
            }
        };
        const KeyResolver::Solution alternativeSolution = {
            GpgME::OpenPGP,
            {createTestKey("sender@example.net", GpgME::OpenPGP)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {createTestKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("prefer-smime@example.net"), {}},
                {QStringLiteral("sender@example.net"), {createTestKey("sender@example.net", GpgME::OpenPGP)}}
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

        verifyProtocolButton(dialog->findChild<QRadioButton *>("openpgp button"), IsVisible, IsUnchecked);
        verifyProtocolButton(dialog->findChild<QRadioButton *>("smime button"), IsVisible, IsChecked);
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
            {createTestKey("sender@example.net", GpgME::OpenPGP)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {createTestKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("prefer-smime@example.net"), {}},
                {QStringLiteral("sender@example.net"), {createTestKey("sender@example.net", GpgME::OpenPGP)}}
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

        verifyProtocolButton(dialog->findChild<QRadioButton *>("openpgp button"), IsHidden, IsChecked);
        verifyProtocolButton(dialog->findChild<QRadioButton *>("smime button"), IsHidden, IsUnchecked);
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
            {createTestKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {}},
                {QStringLiteral("prefer-smime@example.net"), {createTestKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
                {QStringLiteral("sender@example.net"), {createTestKey("sender@example.net", GpgME::CMS)}}
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

        verifyProtocolButton(dialog->findChild<QRadioButton *>("openpgp button"), IsHidden, IsUnchecked);
        verifyProtocolButton(dialog->findChild<QRadioButton *>("smime button"), IsHidden, IsChecked);
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
            {createTestKey("sender@example.net", GpgME::OpenPGP), createTestKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {createTestKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("prefer-smime@example.net"), {createTestKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
                {QStringLiteral("unknown@example.net"), {}},
                {QStringLiteral("sender@example.net"), {createTestKey("sender@example.net", GpgME::OpenPGP), createTestKey("sender@example.net", GpgME::CMS)}}
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

        verifyProtocolButton(dialog->findChild<QCheckBox *>("openpgp button"), IsVisible, IsChecked);
        verifyProtocolButton(dialog->findChild<QCheckBox *>("smime button"), IsVisible, IsChecked);
        verifyProtocolLabels(dialog->findChildren<QLabel *>("protocol label"), 4, IsVisible);
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
            {createTestKey("sender@example.net", GpgME::OpenPGP), createTestKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {createTestKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("unknown@example.net"), {}},
                {QStringLiteral("sender@example.net"), {createTestKey("sender@example.net", GpgME::OpenPGP), createTestKey("sender@example.net", GpgME::CMS)}}
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

        verifyProtocolButton(dialog->findChild<QCheckBox *>("openpgp button"), IsVisible, IsChecked);
        verifyProtocolButton(dialog->findChild<QCheckBox *>("smime button"), IsVisible, IsUnchecked);
        verifyProtocolLabels(dialog->findChildren<QLabel *>("protocol label"), 4, IsHidden);
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
            {createTestKey("sender@example.net", GpgME::OpenPGP), createTestKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("prefer-smime@example.net"), {createTestKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
                {QStringLiteral("unknown@example.net"), {}},
                {QStringLiteral("sender@example.net"), {createTestKey("sender@example.net", GpgME::OpenPGP), createTestKey("sender@example.net", GpgME::CMS)}}
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

        verifyProtocolButton(dialog->findChild<QCheckBox *>("openpgp button"), IsVisible, IsUnchecked);
        verifyProtocolButton(dialog->findChild<QCheckBox *>("smime button"), IsVisible, IsChecked);
        verifyProtocolLabels(dialog->findChildren<QLabel *>("protocol label"), 4, IsHidden);
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
                {QStringLiteral("prefer-openpgp@example.net"), {createTestKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("prefer-smime@example.net"), {createTestKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
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
            {createTestKey("sender@example.net", GpgME::OpenPGP), createTestKey("sender@example.net", GpgME::CMS)},
            {
                {QStringLiteral("prefer-openpgp@example.net"), {createTestKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
                {QStringLiteral("prefer-smime@example.net"), {createTestKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
                {QStringLiteral("unknown@example.net"), {}},
                {QStringLiteral("sender@example.net"), {createTestKey("sender@example.net", GpgME::OpenPGP), createTestKey("sender@example.net", GpgME::CMS)}}
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
};

QTEST_MAIN(NewKeyApprovalDialogTest)
#include "newkeyapprovaldialogtest.moc"
