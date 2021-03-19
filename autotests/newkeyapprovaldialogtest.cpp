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
#include <set>

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

template <typename T>
QList<T *> visibleWidgets(const QList<T *> &widgets)
{
    QList<T *> result;
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
        const QList<KeySelectionCombo *> signingKeyWidgets = dialog->findChildren<KeySelectionCombo *>(QStringLiteral("signing key"));
        QCOMPARE(signingKeyWidgets.size(), 2);
        const auto visibleSigningKeyWidgets = visibleWidgets(signingKeyWidgets);
        QCOMPARE(visibleSigningKeyWidgets.size(), 1);
        for (auto combo: visibleSigningKeyWidgets) {
            QVERIFY(combo);
            QVERIFY2(!combo->defaultKey(GpgME::OpenPGP).isEmpty(), "visible signing key widget should default to OpenPGP key");
        }
        const QList<KeySelectionCombo *> encryptionKeyWidgets = dialog->findChildren<KeySelectionCombo *>(QStringLiteral("encryption key"));
        QCOMPARE(encryptionKeyWidgets.size(), 4);
        const auto visibleEncryptionKeyWidgets = visibleWidgets(encryptionKeyWidgets);
        QCOMPARE(visibleEncryptionKeyWidgets.size(), 3);
        QCOMPARE(visibleEncryptionKeyWidgets[0]->property("address").toString(), sender);
        QVERIFY2(!visibleEncryptionKeyWidgets[0]->defaultKey(GpgME::OpenPGP).isEmpty(),
                 "encryption key widget for sender's OpenPGP key is first visible widget");
        for (auto combo: visibleEncryptionKeyWidgets) {
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
        const QList<KeySelectionCombo *> signingKeyWidgets = dialog->findChildren<KeySelectionCombo *>(QStringLiteral("signing key"));
        QCOMPARE(signingKeyWidgets.size(), 2);
        const auto visibleSigningKeyWidgets = visibleWidgets(signingKeyWidgets);
        QCOMPARE(visibleSigningKeyWidgets.size(), 1);
        for (auto combo: visibleSigningKeyWidgets) {
            QVERIFY(combo);
            QVERIFY2(!combo->defaultKey(GpgME::CMS).isEmpty(), "visible signing key widget should default to S/MIME key");
        }
        const QList<KeySelectionCombo *> encryptionKeyWidgets = dialog->findChildren<KeySelectionCombo *>(QStringLiteral("encryption key"));
        QCOMPARE(encryptionKeyWidgets.size(), 4);
        const auto visibleEncryptionKeyWidgets = visibleWidgets(encryptionKeyWidgets);
        QCOMPARE(visibleEncryptionKeyWidgets.size(), 3);
        QCOMPARE(visibleEncryptionKeyWidgets[0]->property("address").toString(), sender);
        QVERIFY2(!visibleEncryptionKeyWidgets[0]->defaultKey(GpgME::CMS).isEmpty(),
                 "encryption key widget for sender's CMS key is first visible widget");
        for (auto combo: visibleEncryptionKeyWidgets) {
            QVERIFY(combo);
            QVERIFY2(combo->property("address").toString() != sender || !combo->defaultKey(GpgME::CMS).isEmpty(),
                     "encryption key widget for sender's OpenPGP key should be hidden");
        }
    }

    void test_all_resolved_allow_mixed()
    {
        const QStringList unresolvedSenders;
        const QStringList unresolvedRecipients;
        const QString sender = QStringLiteral("sender@example.net");
        bool allowMixed = true;
        GpgME::Protocol forcedProtocol = GpgME::UnknownProtocol;
        GpgME::Protocol presetProtocol = GpgME::UnknownProtocol;
        const auto resolvedSenders = resolved_senders_openpgp_and_smime();
        const auto resolvedRecipients = resolved_recipients_openpgp_and_smime();
        const auto dialog = std::make_unique<NewKeyApprovalDialog>(resolvedSenders,
                                                                   resolvedRecipients,
                                                                   unresolvedSenders,
                                                                   unresolvedRecipients,
                                                                   sender,
                                                                   allowMixed,
                                                                   forcedProtocol,
                                                                   presetProtocol);
        dialog->show();

        const QList<KeySelectionCombo *> signingKeyWidgets = dialog->findChildren<KeySelectionCombo *>(QStringLiteral("signing key"));
        QCOMPARE(signingKeyWidgets.size(), 2);
        for (auto widget : signingKeyWidgets) {
            QVERIFY2(widget->isVisible(), "signing key widget should be visible");
        }
        // first signing key widget should default to sender's OpenPGP key, the other to sender's S/MIME key
        QCOMPARE(signingKeyWidgets[0]->defaultKey(GpgME::OpenPGP),
                 QString::fromLatin1(resolvedSenders["sender@example.net"][0].primaryFingerprint()));
        QCOMPARE(signingKeyWidgets[1]->defaultKey(GpgME::CMS),
                 QString::fromLatin1(resolvedSenders["sender@example.net"][1].primaryFingerprint()));

        const QList<KeySelectionCombo *> encryptionKeyWidgets = dialog->findChildren<KeySelectionCombo *>(QStringLiteral("encryption key"));
        QCOMPARE(encryptionKeyWidgets.size(), 4);
        for (auto widget : encryptionKeyWidgets) {
            QVERIFY2(widget->isVisible(),
                     qPrintable(QString("encryption key widget should be visible for address %1").arg(widget->property("address").toString())));
        }
        // first two encryption key widgets shall be widgets for sender's keys
        QCOMPARE(encryptionKeyWidgets[0]->property("address").toString(), sender);
        QCOMPARE(encryptionKeyWidgets[0]->defaultKey(GpgME::OpenPGP),
                 QString::fromLatin1(resolvedRecipients["sender@example.net"][0].primaryFingerprint()));
        QCOMPARE(encryptionKeyWidgets[1]->property("address").toString(), sender);
        QCOMPARE(encryptionKeyWidgets[1]->defaultKey(GpgME::CMS),
                 QString::fromLatin1(resolvedRecipients["sender@example.net"][1].primaryFingerprint()));
        // further encryption key widgets shall be widgets for keys of recipients
        QCOMPARE(encryptionKeyWidgets[2]->property("address").toString(), QStringLiteral("prefer-openpgp@example.net"));
        QCOMPARE(encryptionKeyWidgets[2]->defaultKey(),
                 QString::fromLatin1(resolvedRecipients["prefer-openpgp@example.net"][0].primaryFingerprint()));
        QCOMPARE(encryptionKeyWidgets[3]->property("address").toString(), QStringLiteral("prefer-smime@example.net"));
        QCOMPARE(encryptionKeyWidgets[3]->defaultKey(),
                 QString::fromLatin1(resolvedRecipients["prefer-smime@example.net"][0].primaryFingerprint()));
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
