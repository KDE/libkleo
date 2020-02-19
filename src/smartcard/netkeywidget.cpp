/*  view/netkeywidget.cpp

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
#include "netkeywidget.h"
#include "nullpinwidget.h"
#include "ui/keytreeview.h"

#include "libkleo_debug.h"

#include "smartcard/netkeycard.h"
#include "models/keylistmodel.h"

#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QPushButton>
#include <QTreeView>

#include <KLocalizedString>
#include <KMessageBox>

using namespace Kleo;
using namespace Kleo::SmartCard;

NetKeyWidget::NetKeyWidget() :
    mSerialNumber(new QLabel),
    mVersionLabel(new QLabel),
    mLearnKeysLabel(new QLabel),
    mErrorLabel(new QLabel),
    mNullPinWidget(new NullPinWidget()),
    mLearnKeysBtn(new QPushButton),
    mChangeNKSPINBtn(new QPushButton),
    mChangeSigGPINBtn(new QPushButton),
    mTreeView(new KeyTreeView(this)),
    mArea(new QScrollArea)
{
    auto vLay = new QVBoxLayout;

    // Set up the scroll are
    mArea->setFrameShape(QFrame::NoFrame);
    mArea->setWidgetResizable(true);
    auto mAreaWidget = new QWidget;
    mAreaWidget->setLayout(vLay);
    mArea->setWidget(mAreaWidget);
    auto scrollLay = new QVBoxLayout(this);
    scrollLay->addWidget(mArea);

    // Add general widgets
    mVersionLabel->setTextInteractionFlags(Qt::TextBrowserInteraction);
    vLay->addWidget(mVersionLabel, 0, Qt::AlignLeft);

    mSerialNumber->setTextInteractionFlags(Qt::TextBrowserInteraction);

    auto hLay1 = new QHBoxLayout;
    hLay1->addWidget(new QLabel(i18n("Serial number:")));
    hLay1->addWidget(mSerialNumber);
    hLay1->addStretch(1);
    vLay->addLayout(hLay1);

    vLay->addWidget(mNullPinWidget);


    auto line1 = new QFrame();
    line1->setFrameShape(QFrame::HLine);
    vLay->addWidget(line1);
    vLay->addWidget(new QLabel(QStringLiteral("<b>%1</b>").arg(i18n("Certificates:"))), 0, Qt::AlignLeft);

    mLearnKeysLabel = new QLabel(i18n("There are unknown certificates on this card."));
    mLearnKeysBtn->setText(i18nc("@action", "Load Certificates"));
    connect(mLearnKeysBtn, &QPushButton::clicked, this, [this] () {
#if 0
        mLearnKeysBtn->setEnabled(false);
        auto cmd = new LearnCardKeysCommand(GpgME::CMS);
        cmd->setParentWidget(this);
        cmd->start();
        TODO libkleo port
        auto icon = KleopatraApplication::instance()->sysTrayIcon();
        if (icon) {
            icon->setLearningInProgress(true);
        }

        connect(cmd, &Command::finished, this, [icon] () {
            ReaderStatus::mutableInstance()->updateStatus();
            icon->setLearningInProgress(false);
        });
#endif
    });

    auto hLay2 = new QHBoxLayout;
    hLay2->addWidget(mLearnKeysLabel);
    hLay2->addWidget(mLearnKeysBtn);
    hLay2->addStretch(1);
    vLay->addLayout(hLay2);

    mErrorLabel->setVisible(false);
    vLay->addWidget(mErrorLabel);

    // The certificate view
    mTreeView->setHierarchicalModel(AbstractKeyListModel::createHierarchicalKeyListModel(mTreeView));
    mTreeView->setHierarchicalView(true);

#if 0
    TODO libkleo port:
    connect(mTreeView->view(), &QAbstractItemView::doubleClicked, this, [this] (const QModelIndex &idx) {
        const auto klm = dynamic_cast<KeyListModelInterface *> (mTreeView->view()->model());
        if (!klm) {
            qCDebug(LIBKLEO_LOG) << "Unhandled Model: " << mTreeView->view()->model()->metaObject()->className();
            return;
        }
        auto cmd = new DetailsCommand(klm->key(idx), nullptr);
        cmd->setParentWidget(this);
        cmd->start();
    });
    vLay->addWidget(mTreeView);
#endif

    // The action area
    auto line2 = new QFrame();
    line2->setFrameShape(QFrame::HLine);
    vLay->addWidget(line2);
    vLay->addWidget(new QLabel(QStringLiteral("<b>%1</b>").arg(i18n("Actions:"))), 0, Qt::AlignLeft);

    mChangeNKSPINBtn->setText(i18nc("NKS is an identifier for a type of keys on a NetKey card", "Change NKS PIN"));
    mChangeSigGPINBtn->setText(i18nc("SigG is an identifier for a type of keys on a NetKey card", "Change SigG PIN"));

    connect(mChangeNKSPINBtn, &QPushButton::clicked, this, [this] () {
            mChangeNKSPINBtn->setEnabled(false);
            doChangePin(false);
        });
    connect(mChangeSigGPINBtn, &QPushButton::clicked, this, [this] () {
            mChangeSigGPINBtn->setEnabled(false);
            doChangePin(true);
        });

    auto hLay3 = new QHBoxLayout();
    hLay3->addWidget(mChangeNKSPINBtn);
    hLay3->addWidget(mChangeSigGPINBtn);
    hLay3->addStretch(1);

    vLay->addLayout(hLay3);
    vLay->addStretch(1);
}

void NetKeyWidget::setCard(const NetKeyCard* card)
{
    mVersionLabel->setText(i18nc("1 is a Version number", "NetKey v%1 Card", card->appVersion()));
    mSerialNumber->setText(card->serialNumber());

    /* According to users of NetKey Cards it is fairly uncommon
     * to use SigG Certificates at all. So it should be optional to set the pins. */
    mNullPinWidget->setVisible(card->hasNKSNullPin() /*|| card->hasSigGNullPin()*/);

    mNullPinWidget->setSigGVisible(false/*card->hasSigGNullPin()*/);
    mNullPinWidget->setNKSVisible(card->hasNKSNullPin());
    mChangeNKSPINBtn->setEnabled(!card->hasNKSNullPin());

    if (card->hasSigGNullPin()) {
        mChangeSigGPINBtn->setText(i18nc("SigG is an identifier for a type of keys on a NetKey card",
                                   "Set SigG PIN"));
    } else {
        mChangeSigGPINBtn->setText(i18nc("SigG is an identifier for a type of keys on a NetKey card",
                                  "Change SigG PIN"));
    }

    mLearnKeysBtn->setEnabled(true);
    mLearnKeysBtn->setVisible(card->canLearnKeys());
    mTreeView->setVisible(!card->canLearnKeys());
    mLearnKeysLabel->setVisible(card->canLearnKeys());

    const auto errMsg = card->errorMsg();
    if (!errMsg.isEmpty()) {
        mErrorLabel->setText(QStringLiteral("<b>%1:</b> %2").arg(i18n("Error")).arg(errMsg));
        mErrorLabel->setVisible(true);
    } else {
        mErrorLabel->setVisible(false);
    }

    const auto keys = card->keys();
    mTreeView->setKeys(keys);
}

void NetKeyWidget::handleResult(const GpgME::Error &err, QPushButton *btn)
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
}

void NetKeyWidget::setSigGPinSettingResult(const GpgME::Error &err)
{
    handleResult(err, mChangeSigGPINBtn);
}

void NetKeyWidget::setNksPinSettingResult(const GpgME::Error &err)
{
    handleResult(err, mChangeNKSPINBtn);
}

void NetKeyWidget::doChangePin(bool sigG)
{
#if 0
    TODO libkleo port:
    if (sigG) {
        ReaderStatus::mutableInstance()
        ->startSimpleTransaction("SCD PASSWD PW1.CH.SIG",
                                 this, "setSigGPinSettingResult");
    } else {
        ReaderStatus::mutableInstance()
        ->startSimpleTransaction("SCD PASSWD PW1.CH",
                                 this, "setNksPinSettingResult");
    }
#endif
}
