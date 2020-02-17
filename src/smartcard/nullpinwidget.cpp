/*  view/nullpinwidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    Copyright (c) 2017 Intevation GmbH

    Kleopatra is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kleopatra is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    In addition, as a special exception, the copyright holders give
    permission to link the code of this program with any edition of
    the Qt library by Trolltech AS, Norway (or with modified versions
    of Qt that use the same license as Qt), and distribute linked
    combinations including the two.  You must obey the GNU General
    Public License in all respects for all of the code used other than
    Qt.  If you modify this file, you may extend this exception to
    your version of the file, but you are not obligated to do so.  If
    you do not wish to do so, delete this exception statement from
    your version.
*/

#include "nullpinwidget.h"

#include "libkleo_debug.h"

#include <gpgme++/error.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>

#include <KLocalizedString>
#include <KMessageBox>

#include "netkeycard.h"

using namespace Kleo;
using namespace Kleo::SmartCard;

NullPinWidget::NullPinWidget()
{
    const auto nullTitle = i18nc("NullPIN is a word that is used all over in the netkey "
                                 "documentation and should be understandable by Netkey cardholders",
                                 "The NullPIN is still active on this card.");
    const auto nullDescription = i18n("You need to set a PIN before you can use the certificates.");
    const auto descriptionLbl = new QLabel(QStringLiteral("<b>%1</b><br/>%2").arg(nullTitle).arg(nullDescription));

    auto vLay = new QVBoxLayout(this);
    vLay->addWidget(descriptionLbl, 0, Qt::AlignCenter);

    mNKSBtn = new QPushButton(i18nc("NKS is an identifier for a type of keys on a NetKey card", "Set NKS PIN"));
    mSigGBtn = new QPushButton(i18nc("SigG is an identifier for a type of keys on a NetKey card", "Set SigG PIN"));

    connect(mNKSBtn, &QPushButton::clicked, this, [this] () {
            mNKSBtn->setEnabled(false);
            doChangePin(false);
        });
    connect(mSigGBtn, &QPushButton::clicked, this, [this] () {
            mSigGBtn->setEnabled(false);
            doChangePin(true);
        });

    auto hLayBtn = new QHBoxLayout;
    hLayBtn->addStretch(1);
    hLayBtn->addWidget(mNKSBtn);
    hLayBtn->addWidget(mSigGBtn);
    hLayBtn->addStretch(1);

    vLay->addLayout(hLayBtn);
}

void NullPinWidget::doChangePin(bool sigG)
{
    auto ret = KMessageBox::warningContinueCancel(this,
            i18n("Setting a PIN is required but <b>can't be reverted</b>.") +
            QStringLiteral("<p>%1</p><p>%2</p>").arg(
                i18n("If you proceed you will be asked to enter a new PIN "
                     "and later to repeat that PIN.")).arg(
                i18n("It will <b>not be possible</b> to recover the "
                     "card if the PIN has been entered wrongly more than 2 times.")),
            i18n("Set initial PIN"),
            KStandardGuiItem::cont(),
            KStandardGuiItem::cancel());

    if (ret != KMessageBox::Continue) {
        return;
    }
#if 0
    TODO libkleo-port
    if (sigG) {
        ReaderStatus::mutableInstance()
        ->startSimpleTransaction("SCD PASSWD --nullpin PW1.CH.SIG",
                                 this, "setSigGPinSettingResult");
    } else {
        ReaderStatus::mutableInstance()
        ->startSimpleTransaction("SCD PASSWD --nullpin PW1.CH",
                                 this, "setNksPinSettingResult");
    }
#endif
}

void NullPinWidget::handleResult(const GpgME::Error &err, QPushButton *btn)
{
    btn->setEnabled(true);
    if (err.isCanceled()) {
        return;
    }
    if (err) {
        KMessageBox::error(this, i18nc("@info",
                           "Failed to set PIN: %1", QString::fromLatin1(err.asString())),
                           i18nc("@title", "Error"));
        return;
    }
    btn->setVisible(false);

    if (!mNKSBtn->isVisible() && !mSigGBtn->isVisible()) {
        // Both pins are set, we can hide.
        setVisible(false);
    }
}

void NullPinWidget::setSigGVisible(bool val)
{
    mSigGBtn->setVisible(val);
}

void NullPinWidget::setNKSVisible(bool val)
{
    mNKSBtn->setVisible(val);
}

void NullPinWidget::setSigGPinSettingResult(const GpgME::Error &err)
{
    handleResult(err, mSigGBtn);
}

void NullPinWidget::setNksPinSettingResult(const GpgME::Error &err)
{
    handleResult(err, mNKSBtn);
}
