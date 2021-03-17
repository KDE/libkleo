/*
    autotests/newkeyapprovaldialogtest.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <Libkleo/KeySelectionCombo>
#include <Libkleo/NewKeyApprovalDialog>

#include <QObject>
#include <QTest>

#include <gpgme++/key.h>

#include <gpgme.h>

#include <memory>

using namespace Kleo;

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

QList<QWidget *> visibleWidgets(const QList<QWidget *> &widgets)
{
    QList<QWidget *> result;
    std::copy_if(widgets.begin(), widgets.end(),
                 std::back_inserter(result),
                 std::mem_fn(&QWidget::isVisible));
    return result;
}
}

class NewKeyApprovalDialogTest: public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void test_all_resolved_exclusive_prefer_OpenPGP()
    {
        const QStringList unresolvedSenders;
        const QStringList unresolvedRecipients;
        const QString sender = QStringLiteral("sender@example.net");
        bool allowMixed = false;
        GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        GpgME::Protocol presetProtocol = GpgME::OpenPGP;
        const auto dialog = std::make_unique<NewKeyApprovalDialog>(resolved_senders_openpgp_and_smime(),
                                                                   resolved_recipients_openpgp_and_smime(),
                                                                   unresolvedSenders,
                                                                   unresolvedRecipients,
                                                                   sender,
                                                                   allowMixed,
                                                                   forcedProtocol,
                                                                   presetProtocol);
        dialog->show();
        const QList<QWidget *> signingKeyWidgets = dialog->findChildren<QWidget *>(QStringLiteral("signing key"));
        QCOMPARE(signingKeyWidgets.size(), 2);
        const auto visibleSigningKeyWidgets = visibleWidgets(signingKeyWidgets);
        QCOMPARE(visibleSigningKeyWidgets.size(), 1);
        for (auto widget : visibleSigningKeyWidgets) {
            KeySelectionCombo *combo = qobject_cast<KeySelectionCombo *>(widget);
            QVERIFY(combo);
            QVERIFY2(!combo->defaultKey(GpgME::OpenPGP).isEmpty(), "visible signing key widget should default to OpenPGP key");
        }
        const QList<QWidget *> encryptionKeyWidgets = dialog->findChildren<QWidget *>(QStringLiteral("encryption key"));
        QCOMPARE(encryptionKeyWidgets.size(), 4);
        const auto visibleEncryptionKeyWidgets = visibleWidgets(encryptionKeyWidgets);
        QCOMPARE(visibleEncryptionKeyWidgets.size(), 3);
        for (auto widget : visibleEncryptionKeyWidgets) {
            KeySelectionCombo *combo = qobject_cast<KeySelectionCombo *>(widget);
            QVERIFY(combo);
            QVERIFY2(combo->property("address").toString() != sender || !combo->defaultKey(GpgME::OpenPGP).isEmpty(),
                     "encryption key widget for sender's CMS key should be hidden");
        }
    }

    void test_all_resolved_exclusive_prefer_SMIME()
    {
        const QStringList unresolvedSenders;
        const QStringList unresolvedRecipients;
        const QString sender = QStringLiteral("sender@example.net");
        bool allowMixed = false;
        GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        GpgME::Protocol presetProtocol = GpgME::CMS;
        const auto dialog = std::make_unique<NewKeyApprovalDialog>(resolved_senders_openpgp_and_smime(),
                                                                   resolved_recipients_openpgp_and_smime(),
                                                                   unresolvedSenders,
                                                                   unresolvedRecipients,
                                                                   sender,
                                                                   allowMixed,
                                                                   forcedProtocol,
                                                                   presetProtocol);
        dialog->show();
        const QList<QWidget *> signingKeyWidgets = dialog->findChildren<QWidget *>(QStringLiteral("signing key"));
        QCOMPARE(signingKeyWidgets.size(), 2);
        const auto visibleSigningKeyWidgets = visibleWidgets(signingKeyWidgets);
        QCOMPARE(visibleSigningKeyWidgets.size(), 1);
        for (auto widget : visibleSigningKeyWidgets) {
            KeySelectionCombo *combo = qobject_cast<KeySelectionCombo *>(widget);
            QVERIFY(combo);
            QVERIFY2(!combo->defaultKey(GpgME::CMS).isEmpty(), "visible signing key widget should default to S/MIME key");
        }
        const QList<QWidget *> encryptionKeyWidgets = dialog->findChildren<QWidget *>(QStringLiteral("encryption key"));
        QCOMPARE(encryptionKeyWidgets.size(), 4);
        const auto visibleEncryptionKeyWidgets = visibleWidgets(encryptionKeyWidgets);
        QCOMPARE(visibleEncryptionKeyWidgets.size(), 3);
        for (auto widget : visibleEncryptionKeyWidgets) {
            KeySelectionCombo *combo = qobject_cast<KeySelectionCombo *>(widget);
            QVERIFY(combo);
            QVERIFY2(combo->property("address").toString() != sender || !combo->defaultKey(GpgME::CMS).isEmpty(),
                     "encryption key widget for sender's OpenPGP key should be hidden");
        }
    }

private:
    QMap<QString, std::vector<GpgME::Key> > resolved_senders_openpgp_and_smime()
    {
        return {
            {QStringLiteral("sender@example.net"), {
                createTestKey("sender@example.net", GpgME::OpenPGP),
                createTestKey("sender@example.net", GpgME::CMS)
            }}
        };
    }

    QMap<QString, std::vector<GpgME::Key> > resolved_recipients_openpgp_and_smime()
    {
        return {
            {QStringLiteral("prefer-openpgp@example.net"), {createTestKey("Full Trust <prefer-openpgp@example.net>", GpgME::OpenPGP)}},
            {QStringLiteral("prefer-smime@example.net"), {createTestKey("Trusted S/MIME <prefer-smime@example.net>", GpgME::CMS)}},
            {QStringLiteral("sender@example.net"), {
                createTestKey("sender@example.net", GpgME::OpenPGP),
                createTestKey("sender@example.net", GpgME::CMS)
            }}
        };
    }
};

QTEST_MAIN(NewKeyApprovalDialogTest)
#include "newkeyapprovaldialogtest.moc"
