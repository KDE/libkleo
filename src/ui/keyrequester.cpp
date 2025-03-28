/*  -*- c++ -*-
    keyrequester.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    Based on kpgpui.cpp
    SPDX-FileCopyrightText: 2001, 2002 the KPGP authors
    See file libkdenetwork/AUTHORS.kpgp for details

    This file is part of KPGP, the KDE PGP/GnuPG support library.

    SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config-libkleo.h>

#include "keyrequester.h"

#include "keyselectiondialog.h"

#include <libkleo/algorithm.h>
#include <libkleo/compliance.h>
#include <libkleo/formatting.h>
#include <libkleo/keyhelpers.h>

#include <KLocalizedString>
#include <KMessageBox>

#include <QGpgME/KeyListJob>

#include <QApplication>
#include <QDialog>
#include <QHBoxLayout>
#include <QPushButton>
#include <QString>

#include <gpgme++/key.h>
#include <gpgme++/keylistresult.h>

using namespace QGpgME;
using namespace Kleo;

Kleo::KeyRequester::KeyRequester(unsigned int allowedKeys, bool multipleKeys, QWidget *parent)
    : QWidget(parent)
    , mOpenPGPBackend(nullptr)
    , mSMIMEBackend(nullptr)
    , mMulti(multipleKeys)
    , mKeyUsage(allowedKeys)
    , mJobs(0)
    , d(nullptr)
{
    init();
}

Kleo::KeyRequester::KeyRequester(QWidget *parent)
    : QWidget(parent)
    , mOpenPGPBackend(nullptr)
    , mSMIMEBackend(nullptr)
    , mMulti(false)
    , mKeyUsage(0)
    , mJobs(0)
    , d(nullptr)
{
    init();
}

void Kleo::KeyRequester::init()
{
    auto hlay = new QHBoxLayout(this);
    hlay->setContentsMargins(0, 0, 0, 0);

    if (DeVSCompliance::isCompliant()) {
        mComplianceIcon = new QLabel{this};
        mComplianceIcon->setPixmap(Formatting::questionIcon().pixmap(22));
    }

    // the label where the key id is to be displayed:
    mLabel = new QLabel(this);
    mLabel->setFrameStyle(QFrame::StyledPanel | QFrame::Sunken);

    // the button to unset any key:
    mEraseButton = new QPushButton(this);
    mEraseButton->setAutoDefault(false);
    mEraseButton->setSizePolicy(QSizePolicy(QSizePolicy::Minimum, QSizePolicy::Minimum));
    mEraseButton->setIcon(
        QIcon::fromTheme(QApplication::isRightToLeft() ? QStringLiteral("edit-clear-locationbar-ltr") : QStringLiteral("edit-clear-locationbar-rtl")));
    mEraseButton->setToolTip(i18nc("@info:tooltip", "Clear"));

    // the button to call the KeySelectionDialog:
    mDialogButton = new QPushButton(i18nc("@action:button", "Change..."), this);
    mDialogButton->setAutoDefault(false);

    if (mComplianceIcon) {
        hlay->addWidget(mComplianceIcon);
    }
    hlay->addWidget(mLabel, 1);
    hlay->addWidget(mEraseButton);
    hlay->addWidget(mDialogButton);

    connect(mEraseButton, &QPushButton::clicked, this, &SigningKeyRequester::slotEraseButtonClicked);
    connect(mDialogButton, &QPushButton::clicked, this, &SigningKeyRequester::slotDialogButtonClicked);

    setSizePolicy(QSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Fixed));

    setAllowedKeys(mKeyUsage);
}

Kleo::KeyRequester::~KeyRequester()
{
}

const std::vector<GpgME::Key> &Kleo::KeyRequester::keys() const
{
    return mKeys;
}

const GpgME::Key &Kleo::KeyRequester::key() const
{
    static const GpgME::Key null = GpgME::Key::null;
    if (mKeys.empty()) {
        return null;
    } else {
        return mKeys.front();
    }
}

void Kleo::KeyRequester::setKeys(const std::vector<GpgME::Key> &keys)
{
    mKeys.clear();
    for (auto it = keys.begin(); it != keys.end(); ++it) {
        if (!it->isNull()) {
            mKeys.push_back(*it);
        }
    }
    updateKeys();
}

void Kleo::KeyRequester::setKey(const GpgME::Key &key)
{
    mKeys.clear();
    if (!key.isNull()) {
        mKeys.push_back(key);
    }
    updateKeys();
}

QString Kleo::KeyRequester::fingerprint() const
{
    if (mKeys.empty()) {
        return QString();
    } else {
        return QLatin1StringView(mKeys.front().primaryFingerprint());
    }
}

QStringList Kleo::KeyRequester::fingerprints() const
{
    QStringList result;
    for (auto it = mKeys.begin(); it != mKeys.end(); ++it) {
        if (!it->isNull()) {
            if (const char *fpr = it->primaryFingerprint()) {
                result.push_back(QLatin1StringView(fpr));
            }
        }
    }
    return result;
}

void Kleo::KeyRequester::setFingerprint(const QString &fingerprint)
{
    startKeyListJob(QStringList(fingerprint));
}

void Kleo::KeyRequester::setFingerprints(const QStringList &fingerprints)
{
    startKeyListJob(fingerprints);
}

void Kleo::KeyRequester::updateKeys()
{
    if (mKeys.empty()) {
        if (mComplianceIcon) {
            mComplianceIcon->setPixmap(Formatting::unavailableIcon().pixmap(22));
            mComplianceIcon->setToolTip(QString{});
        }
        mLabel->clear();
        return;
    }
    if (mKeys.size() > 1) {
        setMultipleKeysEnabled(true);
    }

    QStringList labelTexts;
    QString toolTipText;
    for (std::vector<GpgME::Key>::const_iterator it = mKeys.begin(); it != mKeys.end(); ++it) {
        if (it->isNull()) {
            continue;
        }
        const QString fpr = QLatin1StringView(it->primaryFingerprint());
        const QString keyID = QString::fromLatin1(it->keyID());
        labelTexts.push_back(keyID);
        toolTipText += keyID + QLatin1StringView(": ");
        if (const char *uid = it->userID(0).id()) {
            if (it->protocol() == GpgME::OpenPGP) {
                toolTipText += QString::fromUtf8(uid);
            } else {
                toolTipText += Formatting::prettyDN(uid);
            }
        } else {
            toolTipText += xi18n("<placeholder>unknown</placeholder>");
        }
        toolTipText += QLatin1Char('\n');
    }
    if (mComplianceIcon) {
        if (Kleo::all_of(mKeys, &Kleo::DeVSCompliance::keyIsCompliant)) {
            mComplianceIcon->setPixmap(Formatting::successIcon().pixmap(22));
            mComplianceIcon->setToolTip(DeVSCompliance::name(true));
        } else {
            mComplianceIcon->setPixmap(Formatting::warningIcon().pixmap(22));
            mComplianceIcon->setToolTip(DeVSCompliance::name(false));
        }
    }
    mLabel->setText(labelTexts.join(QLatin1StringView(", ")));
    mLabel->setToolTip(toolTipText);
}

#ifndef __KLEO_UI_SHOW_KEY_LIST_ERROR_H__
#define __KLEO_UI_SHOW_KEY_LIST_ERROR_H__
static void showKeyListError(QWidget *parent, const GpgME::Error &err)
{
    Q_ASSERT(err);
    const QString msg = i18n(
        "<qt><p>An error occurred while fetching "
        "the keys from the backend:</p>"
        "<p><b>%1</b></p></qt>",
        Formatting::errorAsString(err));

    KMessageBox::error(parent, msg, i18nc("@title:window", "Key Listing Failed"));
}
#endif // __KLEO_UI_SHOW_KEY_LIST_ERROR_H__

void Kleo::KeyRequester::startKeyListJob(const QStringList &fingerprints)
{
    if (!mSMIMEBackend && !mOpenPGPBackend) {
        return;
    }

    mTmpKeys.clear();
    mJobs = 0;

    unsigned int count = 0;
    for (QStringList::const_iterator it = fingerprints.begin(); it != fingerprints.end(); ++it) {
        if (!(*it).trimmed().isEmpty()) {
            ++count;
        }
    }

    if (!count) {
        // don't fall into the trap that an empty pattern means
        // "return all keys" :)
        setKey(GpgME::Key::null);
        return;
    }

    if (mOpenPGPBackend) {
        KeyListJob *job = mOpenPGPBackend->keyListJob(false); // local, no sigs
        if (!job) {
            KMessageBox::error(this,
                               i18n("The OpenPGP backend does not support listing keys. "
                                    "Check your installation."),
                               i18nc("@title:window", "Key Listing Failed"));
        } else {
            connect(job, &KeyListJob::result, this, &SigningKeyRequester::slotKeyListResult);
            connect(job, &KeyListJob::nextKey, this, &SigningKeyRequester::slotNextKey);

            const GpgME::Error err =
                job->start(fingerprints, mKeyUsage & Kleo::KeySelectionDialog::SecretKeys && !(mKeyUsage & Kleo::KeySelectionDialog::PublicKeys));

            if (err) {
                showKeyListError(this, err);
            } else {
                ++mJobs;
            }
        }
    }

    if (mSMIMEBackend) {
        KeyListJob *job = mSMIMEBackend->keyListJob(false); // local, no sigs
        if (!job) {
            KMessageBox::error(this,
                               i18n("The S/MIME backend does not support listing keys. "
                                    "Check your installation."),
                               i18nc("@title:window", "Key Listing Failed"));
        } else {
            connect(job, &KeyListJob::result, this, &SigningKeyRequester::slotKeyListResult);
            connect(job, &KeyListJob::nextKey, this, &SigningKeyRequester::slotNextKey);

            const GpgME::Error err =
                job->start(fingerprints, mKeyUsage & Kleo::KeySelectionDialog::SecretKeys && !(mKeyUsage & Kleo::KeySelectionDialog::PublicKeys));

            if (err) {
                showKeyListError(this, err);
            } else {
                ++mJobs;
            }
        }
    }

    if (mJobs > 0) {
        mEraseButton->setEnabled(false);
        mDialogButton->setEnabled(false);
    }
}

void Kleo::KeyRequester::slotNextKey(const GpgME::Key &key)
{
    if (!key.isNull()) {
        mTmpKeys.push_back(key);
    }
}

void Kleo::KeyRequester::slotKeyListResult(const GpgME::KeyListResult &res)
{
    if (res.error()) {
        showKeyListError(this, res.error());
    }

    if (--mJobs <= 0) {
        mEraseButton->setEnabled(true);
        mDialogButton->setEnabled(true);

        setKeys(mTmpKeys);
        mTmpKeys.clear();
    }
}

void Kleo::KeyRequester::slotDialogButtonClicked()
{
    KeySelectionDialog *dlg = mKeys.empty() ? new KeySelectionDialog(mDialogCaption, mDialogMessage, mInitialQuery, mKeyUsage, mMulti, false, this)
                                            : new KeySelectionDialog(mDialogCaption, mDialogCaption, mKeys, mKeyUsage, mMulti, false, this);

    if (dlg->exec() == QDialog::Accepted) {
        if (mMulti) {
            setKeys(dlg->selectedKeys());
        } else {
            setKey(dlg->selectedKey());
        }
        Q_EMIT changed();
    }

    delete dlg;
}

void Kleo::KeyRequester::slotEraseButtonClicked()
{
    if (!mKeys.empty()) {
        Q_EMIT changed();
    }
    mKeys.clear();
    updateKeys();
}

void Kleo::KeyRequester::setDialogCaption(const QString &caption)
{
    mDialogCaption = caption;
}

void Kleo::KeyRequester::setDialogMessage(const QString &msg)
{
    mDialogMessage = msg;
}

bool Kleo::KeyRequester::isMultipleKeysEnabled() const
{
    return mMulti;
}

void Kleo::KeyRequester::setMultipleKeysEnabled(bool multi)
{
    if (multi == mMulti) {
        return;
    }

    if (!multi && !mKeys.empty()) {
        mKeys.erase(mKeys.begin() + 1, mKeys.end());
    }

    mMulti = multi;
    updateKeys();
}

unsigned int Kleo::KeyRequester::allowedKeys() const
{
    return mKeyUsage;
}

void Kleo::KeyRequester::setAllowedKeys(unsigned int keyUsage)
{
    mKeyUsage = keyUsage;
    mOpenPGPBackend = nullptr;
    mSMIMEBackend = nullptr;

    if (mKeyUsage & KeySelectionDialog::OpenPGPKeys) {
        mOpenPGPBackend = openpgp();
    }
    if (mKeyUsage & KeySelectionDialog::SMIMEKeys) {
        mSMIMEBackend = smime();
    }

    if (mOpenPGPBackend && !mSMIMEBackend) {
        mDialogCaption = i18n("OpenPGP Key Selection");
        mDialogMessage = i18n("Please select an OpenPGP key to use.");
    } else if (!mOpenPGPBackend && mSMIMEBackend) {
        mDialogCaption = i18n("S/MIME Key Selection");
        mDialogMessage = i18n("Please select an S/MIME key to use.");
    } else {
        mDialogCaption = i18n("Key Selection");
        mDialogMessage = i18n("Please select an (OpenPGP or S/MIME) key to use.");
    }
}

QPushButton *Kleo::KeyRequester::dialogButton()
{
    return mDialogButton;
}

QPushButton *Kleo::KeyRequester::eraseButton()
{
    return mEraseButton;
}

static inline unsigned int foo(bool openpgp, bool smime, bool trusted, bool valid)
{
    unsigned int result = 0;
    if (openpgp) {
        result |= Kleo::KeySelectionDialog::OpenPGPKeys;
    }
    if (smime) {
        result |= Kleo::KeySelectionDialog::SMIMEKeys;
    }
    if (trusted) {
        result |= Kleo::KeySelectionDialog::TrustedKeys;
    }
    if (valid) {
        result |= Kleo::KeySelectionDialog::ValidKeys;
    }
    return result;
}

static inline unsigned int encryptionKeyUsage(bool openpgp, bool smime, bool trusted, bool valid)
{
    return foo(openpgp, smime, trusted, valid) | Kleo::KeySelectionDialog::EncryptionKeys | Kleo::KeySelectionDialog::PublicKeys;
}

static inline unsigned int signingKeyUsage(bool openpgp, bool smime, bool trusted, bool valid)
{
    return foo(openpgp, smime, trusted, valid) | Kleo::KeySelectionDialog::SigningKeys | Kleo::KeySelectionDialog::SecretKeys;
}

Kleo::EncryptionKeyRequester::EncryptionKeyRequester(bool multi, unsigned int proto, QWidget *parent, bool onlyTrusted, bool onlyValid)
    : KeyRequester(encryptionKeyUsage(proto & OpenPGP, proto & SMIME, onlyTrusted, onlyValid), multi, parent)
    , d(nullptr)
{
}

Kleo::EncryptionKeyRequester::EncryptionKeyRequester(QWidget *parent)
    : KeyRequester(0, false, parent)
    , d(nullptr)
{
}

Kleo::EncryptionKeyRequester::~EncryptionKeyRequester()
{
}

void Kleo::EncryptionKeyRequester::setAllowedKeys(unsigned int proto, bool onlyTrusted, bool onlyValid)
{
    KeyRequester::setAllowedKeys(encryptionKeyUsage(proto & OpenPGP, proto & SMIME, onlyTrusted, onlyValid));
}

Kleo::SigningKeyRequester::SigningKeyRequester(bool multi, unsigned int proto, QWidget *parent, bool onlyTrusted, bool onlyValid)
    : KeyRequester(signingKeyUsage(proto & OpenPGP, proto & SMIME, onlyTrusted, onlyValid), multi, parent)
    , d(nullptr)
{
}

Kleo::SigningKeyRequester::SigningKeyRequester(QWidget *parent)
    : KeyRequester(0, false, parent)
    , d(nullptr)
{
}

Kleo::SigningKeyRequester::~SigningKeyRequester()
{
}

void Kleo::SigningKeyRequester::setAllowedKeys(unsigned int proto, bool onlyTrusted, bool onlyValid)
{
    KeyRequester::setAllowedKeys(signingKeyUsage(proto & OpenPGP, proto & SMIME, onlyTrusted, onlyValid));
}

void Kleo::KeyRequester::virtual_hook(int, void *)
{
}
void Kleo::EncryptionKeyRequester::virtual_hook(int id, void *data)
{
    KeyRequester::virtual_hook(id, data);
}
void Kleo::SigningKeyRequester::virtual_hook(int id, void *data)
{
    KeyRequester::virtual_hook(id, data);
}

#include "moc_keyrequester.cpp"
