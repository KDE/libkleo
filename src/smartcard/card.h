#ifndef SMARTCARD_CARD_H
#define SMARTCARD_CARD_H
/*  smartcard/card.h

    This file is part of Kleopatra, the KDE keymanager
    Copyright (c) 2017 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH

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

#include <vector>
#include <string>

#include <QString>

namespace Kleo
{
namespace SmartCard
{
class ReaderStatus;
/** Class to work with Smartcards or other Hardware tokens. */
class Card
{
public:
    enum AppType {
        UnknownApplication,
        OpenPGPApplication,
        NksApplication,
        P15Application,
        DinSigApplication,
        GeldkarteApplication,

        NumAppTypes
    };

    enum PinState {
        UnknownPinState,
        NullPin,
        PinBlocked,
        NoPin,
        PinOk,

        NumPinStates
    };

    enum Status {
        NoCard,
        CardPresent,
        CardActive,
        CardUsable,

        _NumScdStates,

        CardError = _NumScdStates,

        NumStates
    };

    Card();
    virtual ~Card() {}

    virtual bool operator == (const Card& other) const;
    bool operator != (const Card& other) const;

    void setStatus(Status s);
    Status status() const;

    virtual void setSerialNumber(const std::string &sn);
    std::string serialNumber() const;

    AppType appType() const;
    void setAppType(AppType type);

    void setAppVersion(int version);
    int appVersion() const;

    std::vector<PinState> pinStates() const;
    void setPinStates(const std::vector<PinState> &pinStates);

    void setSlot(int slot);
    int slot() const;

    bool hasNullPin() const;
    void setHasNullPin(bool value);

    bool canLearnKeys() const;
    void setCanLearnKeys(bool value);

    QString errorMsg() const;
    void setErrorMsg(const QString &msg);

private:
    bool mCanLearn;
    bool mHasNullPin;
    Status mStatus;
    std::string mSerialNumber;
    AppType mAppType;
    int mAppVersion;
    std::vector<PinState> mPinStates;
    int mSlot;
    QString mErrMsg;
};
} // namespace Smartcard
} // namespace Kleopatra

#endif // SMARTCARD_CARD_H
