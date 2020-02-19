/*  view/gpgcardwidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    Copyright (c) 2017 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH
    Copytrigh (c) 2020 g10 Code GmbH

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

#include "gpgcardwidget.h"
#include "openpgpcard.h"
#include "netkeycard.h"
#include "pgpcardwidget.h"
#include "netkeywidget.h"
#include "cardmanager.h"

#include "libkleo_debug.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QStackedWidget>

#include <KLocalizedString>

using namespace Kleo;
using namespace Kleo::SmartCard;

namespace {
class PlaceHolderWidget: public QWidget
{
    Q_OBJECT
public:
    PlaceHolderWidget()
    {
        auto lay = new QVBoxLayout;
        lay->addStretch(-1);

        const QStringList supported = QStringList() << QStringLiteral("OpenPGP > v2.0")
                                                    << QStringLiteral("YubiKey")
                                                    << QStringLiteral("Gnuk Token")
                                                    << QStringLiteral("NetKey v3");
        lay->addWidget(new QLabel(QStringLiteral("\t\t<h3>") +
                                  i18n("Please insert a compatible smartcard.") + QStringLiteral("</h3>")));
        lay->addSpacing(10);
        lay->addWidget(new QLabel(QStringLiteral("\t\t") +
                       i18n("Kleopatra currently supports the following card types:") +
                            QStringLiteral("<ul><li>") + supported.join(QLatin1String("</li><li>")) +
                            QStringLiteral("</li></ul>")));
        lay->addSpacing(10);
        lay->addWidget(new QLabel(i18n("Refresh the view (F5) to update the smartcard status.")));
        lay->addStretch(-1);

        auto hLay = new QHBoxLayout(this);
        hLay->addStretch(-1);
        hLay->addLayout(lay);
        hLay->addStretch(-1);
        lay->addStretch(-1);
    }
};
} // namespace

class GpgCardWidget::Private
{
public:
    Private(GpgCardWidget *qq) : q(qq)
    {
        QVBoxLayout *vLay = new QVBoxLayout(q);

        mStack = new QStackedWidget;
        vLay->addWidget(mStack);

        mPGPCardWidget = new PGPCardWidget;
        mStack->addWidget(mPGPCardWidget);

        mNetKeyWidget = new NetKeyWidget;
        mStack->addWidget(mNetKeyWidget);

        mPlaceHolderWidget = new PlaceHolderWidget;
        mStack->addWidget(mPlaceHolderWidget);

        mStack->setCurrentWidget(mPlaceHolderWidget);

        connect (CardManager::instance(), &CardManager::cardsMayHaveChanged, q, [this] () {
                const auto cards = CardManager::instance()->cards();
                if (!cards.size()) {
                    setCard(std::shared_ptr<Card>(nullptr));
                } else {
                    // No support for multiple reader / cards currently
                    setCard(cards[0]);
                }
            });
    }

    void setCard(std::shared_ptr<Card> card)
    {
        if (!card) {
            qCDebug(LIBKLEO_LOG) << "No card parsable";
            mStack->setCurrentWidget(mPlaceHolderWidget);
        }
        if (card->appType() == Card::OpenPGPApplication) {
            mPGPCardWidget->setCard(static_cast<OpenPGPCard *> (card.get()));
            mStack->setCurrentWidget(mPGPCardWidget);
        } else if (card->appType() == Card::NksApplication) {
            mNetKeyWidget->setCard(static_cast<NetKeyCard *> (card.get()));
            mStack->setCurrentWidget(mNetKeyWidget);
        } else {
            qCDebug(LIBKLEO_LOG) << "Ignoring unknown card: " << card->serialNumber();
            mStack->setCurrentWidget(mPlaceHolderWidget);
        }
    }

private:
    GpgCardWidget *q;
    NetKeyWidget *mNetKeyWidget;
    PGPCardWidget *mPGPCardWidget;
    PlaceHolderWidget *mPlaceHolderWidget;
    QStackedWidget *mStack;
};

GpgCardWidget::GpgCardWidget(QWidget *parent):
    QWidget(parent),
    d(new Private(this))
{
}

void GpgCardWidget::reload()
{
    CardManager::instance()->startCardList();
}

#include "gpgcardwidget.moc"
