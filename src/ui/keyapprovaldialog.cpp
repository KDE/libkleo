/*  -*- c++ -*-
    keyapprovaldialog.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    Based on kpgpui.h
    SPDX-FileCopyrightText: 2001, 2002 the KPGP authors
    See file libkdenetwork/AUTHORS.kpgp for details

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "keyapprovaldialog.h"

#include "keyrequester.h"

#include <KLocalizedString>
#include <KSeparator>

#include <QApplication>
#include <QComboBox>
#include <QDesktopWidget>
#include <QDialogButtonBox>
#include <QGridLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QStringList>
#include <QVBoxLayout>

#include <gpgme++/key.h>
#include <qgpgme/protocol.h>

static Kleo::EncryptionPreference cb2pref(int i)
{
    switch (i) {
    default:
    case 0: return Kleo::UnknownPreference;
    case 1: return Kleo::NeverEncrypt;
    case 2: return Kleo::AlwaysEncrypt;
    case 3: return Kleo::AlwaysEncryptIfPossible;
    case 4: return Kleo::AlwaysAskForEncryption;
    case 5: return Kleo::AskWheneverPossible;
    }
}

static int pref2cb(Kleo::EncryptionPreference p)
{
    switch (p) {
    default:                            return 0;
    case Kleo::NeverEncrypt:            return 1;
    case Kleo::AlwaysEncrypt:           return 2;
    case Kleo::AlwaysEncryptIfPossible: return 3;
    case Kleo::AlwaysAskForEncryption:  return 4;
    case Kleo::AskWheneverPossible:     return 5;
    }
}

static QStringList preferencesStrings()
{
    return QStringList() << xi18n("<placeholder>none</placeholder>")
           << i18n("Never Encrypt with This Key")
           << i18n("Always Encrypt with This Key")
           << i18n("Encrypt Whenever Encryption is Possible")
           << i18n("Always Ask")
           << i18n("Ask Whenever Encryption is Possible");
}

class Q_DECL_HIDDEN Kleo::KeyApprovalDialog::Private
{
public:
    Private() {}

    Kleo::KeyRequester *selfRequester = nullptr;
    QStringList addresses;
    std::vector<Kleo::KeyRequester *> requesters;
    std::vector<QComboBox *> preferences;
    bool prefsChanged = false;
};

Kleo::KeyApprovalDialog::KeyApprovalDialog(const std::vector<Item> &recipients,
        const std::vector<GpgME::Key> &sender,
        QWidget *parent)
    : QDialog(parent),
      d(new Private())
{
    setWindowTitle(i18nc("@title:window", "Encryption Key Approval"));
    auto mainLayout = new QVBoxLayout(this);
    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    QPushButton *okButton = buttonBox->button(QDialogButtonBox::Ok);
    okButton->setShortcut(Qt::CTRL | Qt::Key_Return);
    connect(buttonBox, &QDialogButtonBox::accepted, this, &KeyApprovalDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &KeyApprovalDialog::reject);
    okButton->setDefault(true);
    Q_ASSERT(!recipients.empty());

    QFrame *page = new QFrame(this);
    mainLayout->addWidget(page);
    mainLayout->addWidget(buttonBox);
    auto vlay = new QVBoxLayout(page);
    vlay->setContentsMargins(0, 0, 0, 0);

    vlay->addWidget(new QLabel(i18n("The following keys will be used for encryption:"), page));

    auto sv = new QScrollArea(page);
    sv->setWidgetResizable(true);
    vlay->addWidget(sv);

    QWidget *view = new QWidget(sv->viewport());

    auto glay = new QGridLayout(view);
    glay->setColumnStretch(1, 1);
    sv->setWidget(view);

    int row = -1;

    if (!sender.empty()) {
        ++row;
        glay->addWidget(new QLabel(i18n("Your keys:"), view), row, 0);
        d->selfRequester = new EncryptionKeyRequester(true, EncryptionKeyRequester::AllProtocols, view);
        d->selfRequester->setKeys(sender);
        glay->addWidget(d->selfRequester, row, 1);
        ++row;
        glay->addWidget(new KSeparator(Qt::Horizontal, view), row, 0, 1, 2);
    }

    const QStringList prefs = preferencesStrings();

    for (auto it = recipients.begin(); it != recipients.end(); ++it) {
        ++row;
        glay->addWidget(new QLabel(i18n("Recipient:"), view), row, 0);
        glay->addWidget(new QLabel(it->address, view), row, 1);
        d->addresses.push_back(it->address);

        ++row;
        glay->addWidget(new QLabel(i18n("Encryption keys:"), view), row, 0);
        KeyRequester *req = new EncryptionKeyRequester(true, EncryptionKeyRequester::AllProtocols, view);
        req->setKeys(it->keys);
        glay->addWidget(req, row, 1);
        d->requesters.push_back(req);

        ++row;
        glay->addWidget(new QLabel(i18n("Encryption preference:"), view), row, 0);
        auto cb = new QComboBox(view);
        cb->setEditable(false);
        cb->addItems(prefs);
        glay->addWidget(cb, row, 1);
        cb->setCurrentIndex(pref2cb(it->pref));
        connect(cb, QOverload<int>::of(&QComboBox::activated), this, &KeyApprovalDialog::slotPrefsChanged);
        d->preferences.push_back(cb);
    }

    QSize size = sizeHint();

    // don't make the dialog too large
    const QRect desk = QApplication::desktop()->screenGeometry(this);
    resize(QSize(qMin(size.width(), 3 * desk.width() / 4),
                 qMin(size.height(), 7 * desk.height() / 8)));
}

Kleo::KeyApprovalDialog::~KeyApprovalDialog()
{
    delete d;
}

std::vector<GpgME::Key> Kleo::KeyApprovalDialog::senderKeys() const
{
    return d->selfRequester ? d->selfRequester->keys() : std::vector<GpgME::Key>();
}

std::vector<Kleo::KeyApprovalDialog::Item> Kleo::KeyApprovalDialog::items() const
{
    Q_ASSERT(d->requesters.size() == static_cast<unsigned int>(d->addresses.size()));
    Q_ASSERT(d->requesters.size() == d->preferences.size());

    std::vector<Item> result;
    result.reserve(d->requesters.size());
    QStringList::const_iterator ait = d->addresses.constBegin();
    auto rit = d->requesters.begin();
    auto cit = d->preferences.begin();
    while (ait != d->addresses.constEnd()) {
        result.push_back(Item(*ait++, (*rit++)->keys(), cb2pref((*cit++)->currentIndex())));
    }
    return result;
}

bool Kleo::KeyApprovalDialog::preferencesChanged() const
{
    return d->prefsChanged;
}

void Kleo::KeyApprovalDialog::slotPrefsChanged()
{
    d->prefsChanged = true;
}

