/*
    cryptoconfigdialog.h

    This file is part of kgpgcertmanager
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "cryptoconfigdialog.h"
#include "cryptoconfigmodule.h"
#include <KLocalizedString>
#include <KAcceleratorManager>
#include <QDialogButtonBox>
#include <QPushButton>
#include <KGuiItem>
#include <QVBoxLayout>

Kleo::CryptoConfigDialog::CryptoConfigDialog(QGpgME::CryptoConfig *config, QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(i18nc("@title:window", "Configure GnuPG Backend"));
    auto mainLayout = new QVBoxLayout(this);
    mButtonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel | QDialogButtonBox::RestoreDefaults | QDialogButtonBox::Apply, this);
    QPushButton *okButton = mButtonBox->button(QDialogButtonBox::Ok);
    okButton->setShortcut(Qt::CTRL | Qt::Key_Return);
    auto user1Button = new QPushButton(this);
    mButtonBox->addButton(user1Button, QDialogButtonBox::ActionRole);
    connect(mButtonBox, &QDialogButtonBox::accepted, this, &CryptoConfigDialog::accept);
    connect(mButtonBox, &QDialogButtonBox::rejected, this, &CryptoConfigDialog::reject);
    okButton->setDefault(true);
    setModal(true);
    KGuiItem::assign(user1Button, KGuiItem(i18n("&Reset")));

    mMainWidget = new CryptoConfigModule(config, this);
    mainLayout->addWidget(mMainWidget);
    mainLayout->addWidget(mButtonBox);

    connect(mMainWidget, &CryptoConfigModule::changed, this, &CryptoConfigDialog::slotChanged);
    mButtonBox->button(QDialogButtonBox::Apply)->setEnabled(false);
    if (mMainWidget->hasError()) {
        mButtonBox->button(QDialogButtonBox::RestoreDefaults)->setVisible(false);
        user1Button->setVisible(false);
        mButtonBox->button(QDialogButtonBox::Apply)->setVisible(false);
        okButton->setVisible(false);
    }

    // Automatically assign accelerators
    KAcceleratorManager::manage(this);
    connect(user1Button, &QPushButton::clicked, this, &CryptoConfigDialog::slotUser1);
    connect(mButtonBox->button(QDialogButtonBox::Cancel), &QPushButton::clicked, this, &CryptoConfigDialog::slotCancel);
    connect(okButton, &QPushButton::clicked, this, &CryptoConfigDialog::slotOk);
    connect(mButtonBox->button(QDialogButtonBox::RestoreDefaults), &QPushButton::clicked, this, &CryptoConfigDialog::slotDefault);
    connect(mButtonBox->button(QDialogButtonBox::Apply), &QPushButton::clicked, this, &CryptoConfigDialog::slotApply);
}

void Kleo::CryptoConfigDialog::slotOk()
{
    slotApply();
    accept();
}

void Kleo::CryptoConfigDialog::slotCancel()
{
    mMainWidget->cancel();
    reject();
}

void Kleo::CryptoConfigDialog::slotDefault()
{
    mMainWidget->defaults();
    slotChanged();
}

void Kleo::CryptoConfigDialog::slotApply()
{
    mMainWidget->save();
    mButtonBox->button(QDialogButtonBox::Apply)->setEnabled(false);
}

void Kleo::CryptoConfigDialog::slotUser1() // reset
{
    mMainWidget->reset();
    mButtonBox->button(QDialogButtonBox::Apply)->setEnabled(false);
}

void Kleo::CryptoConfigDialog::slotChanged()
{
    mButtonBox->button(QDialogButtonBox::Apply)->setEnabled(true);
}

