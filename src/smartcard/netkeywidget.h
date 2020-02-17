/*  view/netkeywidget.h

    This file is part of Kleopatra, the KDE keymanager
    Copyright (c) 2017 Intevation GmbH
                  2020 g10 Code GmbH

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
#ifndef VIEW_NETKEYWIDGET_H
#define VIEW_NETKEYWIDGET_H

#include <QWidget>
#include <gpgme++/error.h>

#include <string>

#include "kleo_export.h"

class QLabel;
class QPushButton;
class QScrollArea;

namespace Kleo
{
class NullPinWidget;
class KeyTreeView;

namespace SmartCard
{
class NetKeyCard;
} // namespace SmartCard

class KLEO_EXPORT NetKeyWidget: public QWidget
{
    Q_OBJECT
public:
    NetKeyWidget();

    void setCard(const SmartCard::NetKeyCard* card);

private:
    void handleResult(const GpgME::Error &err, QPushButton *btn);
    void doChangePin(bool sigG);

private Q_SLOTS:
    void setSigGPinSettingResult(const GpgME::Error &err);
    void setNksPinSettingResult(const GpgME::Error &err);

private:
    QLabel *mSerialNumber,
           *mVersionLabel,
           *mLearnKeysLabel,
           *mErrorLabel;
    NullPinWidget *mNullPinWidget;
    QPushButton *mLearnKeysBtn,
                *mChangeNKSPINBtn,
                *mChangeSigGPINBtn;
    KeyTreeView *mTreeView;
    QScrollArea *mArea;
};
} // namespace Kleo

#endif // VIEW_NETKEYWIDGET_H
