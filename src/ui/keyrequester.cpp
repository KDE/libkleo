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

class KeyRequester::Private
{
public:
    Private(QWidget *q, unsigned int allowedKeys, bool multipleKeys)
        : mMulti(multipleKeys)
        , mKeyUsage(allowedKeys)
    {
        init(q);
    }

    void init(QWidget *q);

    const QGpgME::Protocol *mOpenPGPBackend = nullptr;
    const QGpgME::Protocol *mSMIMEBackend = nullptr;
    QLabel *mComplianceIcon = nullptr;
    QLabel *mLabel = nullptr;
    QPushButton *mEraseButton = nullptr;
    QPushButton *mDialogButton = nullptr;
    QString mDialogCaption, mDialogMessage, mInitialQuery;
    bool mMulti = false;
    unsigned int mKeyUsage = 0;
    int mJobs = 0;
    std::vector<GpgME::Key> mKeys;
    std::vector<GpgME::Key> mTmpKeys;
};

void KeyRequester::Private::init(QWidget *q)
{
    auto hlay = new QHBoxLayout(q);
    hlay->setContentsMargins(0, 0, 0, 0);

    if (DeVSCompliance::isCompliant()) {
        mComplianceIcon = new QLabel{q};
        mComplianceIcon->setPixmap(Formatting::questionIcon().pixmap(22));
    }

    // the label where the key id is to be displayed:
    mLabel = new QLabel(q);
    mLabel->setFrameStyle(QFrame::StyledPanel | QFrame::Sunken);

    // the button to unset any key:
    mEraseButton = new QPushButton(q);
    mEraseButton->setAutoDefault(false);
    mEraseButton->setSizePolicy(QSizePolicy(QSizePolicy::Minimum, QSizePolicy::Minimum));
    mEraseButton->setIcon(
        QIcon::fromTheme(QApplication::isRightToLeft() ? QStringLiteral("edit-clear-locationbar-ltr") : QStringLiteral("edit-clear-locationbar-rtl")));
    mEraseButton->setToolTip(i18nc("@info:tooltip", "Clear"));

    // the button to call the KeySelectionDialog:
    mDialogButton = new QPushButton(i18nc("@action:button", "Change..."), q);
    mDialogButton->setAutoDefault(false);

    if (mComplianceIcon) {
        hlay->addWidget(mComplianceIcon);
    }
    hlay->addWidget(mLabel, 1);
    hlay->addWidget(mEraseButton);
    hlay->addWidget(mDialogButton);
}

Kleo::KeyRequester::KeyRequester(unsigned int allowedKeys, bool multipleKeys, QWidget *parent)
    : QWidget(parent)
    , d{std::make_unique<Private>(this, allowedKeys, multipleKeys)}
{
    connect(d->mEraseButton, &QPushButton::clicked, this, &SigningKeyRequester::slotEraseButtonClicked);
    connect(d->mDialogButton, &QPushButton::clicked, this, &SigningKeyRequester::slotDialogButtonClicked);

    setSizePolicy(QSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Fixed));

    setAllowedKeys(d->mKeyUsage);
}

Kleo::KeyRequester::KeyRequester(QWidget *parent)
    : KeyRequester{0, false, parent}
{
}

Kleo::KeyRequester::~KeyRequester() = default;

const std::vector<GpgME::Key> &Kleo::KeyRequester::keys() const
{
    return d->mKeys;
}

const GpgME::Key &Kleo::KeyRequester::key() const
{
    static const GpgME::Key null = GpgME::Key::null;
    if (d->mKeys.empty()) {
        return null;
    } else {
        return d->mKeys.front();
    }
}

void Kleo::KeyRequester::setKeys(const std::vector<GpgME::Key> &keys)
{
    d->mKeys.clear();
    for (const auto &key : keys) {
        if (!key.isNull()) {
            d->mKeys.push_back(key);
        }
    }
    updateKeys();
}

void Kleo::KeyRequester::setKey(const GpgME::Key &key)
{
    d->mKeys.clear();
    if (!key.isNull()) {
        d->mKeys.push_back(key);
    }
    updateKeys();
}

QString Kleo::KeyRequester::fingerprint() const
{
    if (d->mKeys.empty()) {
        return QString();
    } else {
        return QLatin1StringView(d->mKeys.front().primaryFingerprint());
    }
}

QStringList Kleo::KeyRequester::fingerprints() const
{
    QStringList result;
    for (const GpgME::Key &key : d->mKeys) {
        if (!key.isNull()) {
            if (const char *fpr = key.primaryFingerprint()) {
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
    if (d->mKeys.empty()) {
        if (d->mComplianceIcon) {
            d->mComplianceIcon->setPixmap(Formatting::unavailableIcon().pixmap(22));
            d->mComplianceIcon->setToolTip(QString{});
        }
        d->mLabel->clear();
        return;
    }
    if (d->mKeys.size() > 1) {
        setMultipleKeysEnabled(true);
    }

    QStringList labelTexts;
    QString toolTipText;
    for (const GpgME::Key &key : d->mKeys) {
        if (key.isNull()) {
            continue;
        }
        const QString fpr = QLatin1StringView(key.primaryFingerprint());
        const QString keyID = QString::fromLatin1(key.keyID());
        labelTexts.push_back(keyID);
        toolTipText += keyID + QLatin1StringView(": ");
        if (const char *uid = key.userID(0).id()) {
            if (key.protocol() == GpgME::OpenPGP) {
                toolTipText += QString::fromUtf8(uid);
            } else {
                toolTipText += Formatting::prettyDN(uid);
            }
        } else {
            toolTipText += xi18n("<placeholder>unknown</placeholder>");
        }
        toolTipText += QLatin1Char('\n');
    }
    if (d->mComplianceIcon) {
        if (std::ranges::all_of(d->mKeys, &Kleo::DeVSCompliance::keyIsCompliant)) {
            d->mComplianceIcon->setPixmap(Formatting::successIcon().pixmap(22));
            d->mComplianceIcon->setToolTip(DeVSCompliance::name(true));
        } else {
            d->mComplianceIcon->setPixmap(Formatting::warningIcon().pixmap(22));
            d->mComplianceIcon->setToolTip(DeVSCompliance::name(false));
        }
    }
    d->mLabel->setText(labelTexts.join(QLatin1StringView(", ")));
    d->mLabel->setToolTip(toolTipText);
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
    if (!d->mSMIMEBackend && !d->mOpenPGPBackend) {
        return;
    }

    d->mTmpKeys.clear();
    d->mJobs = 0;

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

    if (d->mOpenPGPBackend) {
        KeyListJob *job = d->mOpenPGPBackend->keyListJob(false); // local, no sigs
        if (!job) {
            KMessageBox::error(this,
                               i18n("The OpenPGP backend does not support listing keys. "
                                    "Check your installation."),
                               i18nc("@title:window", "Key Listing Failed"));
        } else {
            connect(job, &KeyListJob::result, this, &SigningKeyRequester::slotKeyListResult);
            connect(job, &KeyListJob::nextKey, this, &SigningKeyRequester::slotNextKey);

            const GpgME::Error err =
                job->start(fingerprints, d->mKeyUsage & Kleo::KeySelectionDialog::SecretKeys && !(d->mKeyUsage & Kleo::KeySelectionDialog::PublicKeys));

            if (err) {
                showKeyListError(this, err);
            } else {
                d->mJobs += 1;
            }
        }
    }

    if (d->mSMIMEBackend) {
        KeyListJob *job = d->mSMIMEBackend->keyListJob(false); // local, no sigs
        if (!job) {
            KMessageBox::error(this,
                               i18n("The S/MIME backend does not support listing keys. "
                                    "Check your installation."),
                               i18nc("@title:window", "Key Listing Failed"));
        } else {
            connect(job, &KeyListJob::result, this, &SigningKeyRequester::slotKeyListResult);
            connect(job, &KeyListJob::nextKey, this, &SigningKeyRequester::slotNextKey);

            const GpgME::Error err =
                job->start(fingerprints, d->mKeyUsage & Kleo::KeySelectionDialog::SecretKeys && !(d->mKeyUsage & Kleo::KeySelectionDialog::PublicKeys));

            if (err) {
                showKeyListError(this, err);
            } else {
                d->mJobs += 1;
            }
        }
    }

    if (d->mJobs > 0) {
        d->mEraseButton->setEnabled(false);
        d->mDialogButton->setEnabled(false);
    }
}

void Kleo::KeyRequester::slotNextKey(const GpgME::Key &key)
{
    if (!key.isNull()) {
        d->mTmpKeys.push_back(key);
    }
}

void Kleo::KeyRequester::slotKeyListResult(const GpgME::KeyListResult &res)
{
    if (res.error()) {
        showKeyListError(this, res.error());
    }

    d->mJobs -= 1;
    if (d->mJobs <= 0) {
        d->mEraseButton->setEnabled(true);
        d->mDialogButton->setEnabled(true);

        setKeys(d->mTmpKeys);
        d->mTmpKeys.clear();
    }
}

void Kleo::KeyRequester::slotDialogButtonClicked()
{
    KeySelectionDialog *dlg = d->mKeys.empty()
        ? new KeySelectionDialog(d->mDialogCaption, d->mDialogMessage, d->mInitialQuery, d->mKeyUsage, d->mMulti, false, this)
        : new KeySelectionDialog(d->mDialogCaption, d->mDialogCaption, d->mKeys, d->mKeyUsage, d->mMulti, false, this);

    if (dlg->exec() == QDialog::Accepted) {
        if (d->mMulti) {
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
    if (!d->mKeys.empty()) {
        Q_EMIT changed();
    }
    d->mKeys.clear();
    updateKeys();
}

void Kleo::KeyRequester::setDialogCaption(const QString &caption)
{
    d->mDialogCaption = caption;
}

void Kleo::KeyRequester::setDialogMessage(const QString &msg)
{
    d->mDialogMessage = msg;
}

bool Kleo::KeyRequester::isMultipleKeysEnabled() const
{
    return d->mMulti;
}

void Kleo::KeyRequester::setMultipleKeysEnabled(bool multi)
{
    if (multi == d->mMulti) {
        return;
    }

    if (!multi && !d->mKeys.empty()) {
        d->mKeys.erase(d->mKeys.begin() + 1, d->mKeys.end());
    }

    d->mMulti = multi;
    updateKeys();
}

unsigned int Kleo::KeyRequester::allowedKeys() const
{
    return d->mKeyUsage;
}

void Kleo::KeyRequester::setAllowedKeys(unsigned int keyUsage)
{
    d->mKeyUsage = keyUsage;
    d->mOpenPGPBackend = nullptr;
    d->mSMIMEBackend = nullptr;

    if (d->mKeyUsage & KeySelectionDialog::OpenPGPKeys) {
        d->mOpenPGPBackend = openpgp();
    }
    if (d->mKeyUsage & KeySelectionDialog::SMIMEKeys) {
        d->mSMIMEBackend = smime();
    }

    if (d->mOpenPGPBackend && !d->mSMIMEBackend) {
        d->mDialogCaption = i18n("OpenPGP Key Selection");
        d->mDialogMessage = i18n("Please select an OpenPGP key to use.");
    } else if (!d->mOpenPGPBackend && d->mSMIMEBackend) {
        d->mDialogCaption = i18n("S/MIME Key Selection");
        d->mDialogMessage = i18n("Please select an S/MIME key to use.");
    } else {
        d->mDialogCaption = i18n("Key Selection");
        d->mDialogMessage = i18n("Please select an (OpenPGP or S/MIME) key to use.");
    }
}

void KeyRequester::setInitialQuery(const QString &s)
{
    d->mInitialQuery = s;
}

const QString &KeyRequester::initialQuery() const
{
    return d->mInitialQuery;
}

QPushButton *Kleo::KeyRequester::dialogButton()
{
    return d->mDialogButton;
}

QPushButton *Kleo::KeyRequester::eraseButton()
{
    return d->mEraseButton;
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

class EncryptionKeyRequester::Private
{
};

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

Kleo::EncryptionKeyRequester::~EncryptionKeyRequester() = default;

void Kleo::EncryptionKeyRequester::setAllowedKeys(unsigned int proto, bool onlyTrusted, bool onlyValid)
{
    KeyRequester::setAllowedKeys(encryptionKeyUsage(proto & OpenPGP, proto & SMIME, onlyTrusted, onlyValid));
}

class SigningKeyRequester::Private
{
};

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

Kleo::SigningKeyRequester::~SigningKeyRequester() = default;

void Kleo::SigningKeyRequester::setAllowedKeys(unsigned int proto, bool onlyTrusted, bool onlyValid)
{
    KeyRequester::setAllowedKeys(signingKeyUsage(proto & OpenPGP, proto & SMIME, onlyTrusted, onlyValid));
}

#include "moc_keyrequester.cpp"
