/*  smartcard/card.h

    This file is part of Kleopatra, the KDE keymanager
    Copyright (c) 2017 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH
    Copyright (c) 2020 by g10 Code GmbH

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

#include "card.h"

#include <QString>
#include <QMap>
#include <QStringList>
#include <QRegExp>

#include "libkleo_debug.h"

using namespace Kleo;
using namespace Kleo::SmartCard;

class Card::Private
{
public:
    Private(): mCanLearn(false),
               mHasNullPin(false),
               mStatus(Status::NoCard),
               mAppType(UnknownApplication),
               mAppVersion(-1)
    {
    }

    Private(const QString &gpgOutput)
    {
        const auto lines = gpgOutput.split(QRegExp("[\r\n]"),
                                           QString::SkipEmptyParts);
        for (const auto &line: lines) {
            auto words = line.split(QLatin1Char(':'));
            if (words.size () < 2) {
                qCDebug(LIBKLEO_LOG) << "Failed to parse line:" << line;
                continue;
            }
            QString key = words.takeFirst ();
            if (key.startsWith(QLatin1Char(' '))) {
                qCDebug(LIBKLEO_LOG) << "Ignoring subline:" << line;
                continue;
            }
            key.remove(QRegExp(" \\.*$"));
            mProperties.insert(key, words);
        }

        mReader = getSingleProperty("Reader");
        mSerialNumber = getSingleProperty("Serial number").toStdString();
    }

    QString getSingleProperty(const char *val) const
    {
        if (!val) {
            return QString();
        }
        const auto list = mProperties.value(QLatin1String(val));
        if (list.empty()) {
            return QString();
        }
        return list.first();
    }

    QString mReader;
    bool mCanLearn;
    bool mHasNullPin;
    Status mStatus;
    std::string mSerialNumber;
    AppType mAppType;
    int mAppVersion;
    std::vector<PinState> mPinStates;
    int mSlot;
    QString mErrMsg;
    QMap<QString, QStringList> mProperties;
};

Card::Card(): d(new Private()) {
}

Card::Card(const QString &gpgOutput): d(new Private(gpgOutput)) {
}

QString Card::getSingleProperty(const char *propName) const
{
    return d->getSingleProperty(propName);
}

void Card::setStatus(Status s)
{
    d->mStatus = s;
}

Card::Status Card::status() const
{
    return d->mStatus;
}

void Card::setSerialNumber(const std::string &sn)
{
    d->mSerialNumber = sn;
}

std::string Card::serialNumber() const
{
    return d->mSerialNumber;
}

Card::AppType Card::appType() const
{
    return d->mAppType;
}

void Card::setAppType(AppType t)
{
    d->mAppType = t;
}

void Card::setAppVersion(int version)
{
    d->mAppVersion = version;
}

int Card::appVersion() const
{
    return d->mAppVersion;
}

std::vector<Card::PinState> Card::pinStates() const
{
    return d->mPinStates;
}

void Card::setPinStates(const std::vector<PinState> &pinStates)
{
    d->mPinStates = pinStates;
}

void Card::setSlot(int slot)
{
    d->mSlot = slot;
}

int Card::slot() const
{
    return d->mSlot;
}

bool Card::hasNullPin() const
{
    return d->mHasNullPin;
}

void Card::setHasNullPin(bool value)
{
    d->mHasNullPin = value;
}

bool Card::canLearnKeys() const
{
    return d->mCanLearn;
}

void Card::setCanLearnKeys(bool value)
{
    d->mCanLearn = value;
}

bool Card::operator == (const Card& other) const
{
    return d->mStatus == other.status()
        && d->mSerialNumber == other.serialNumber()
        && d->mAppType == other.appType()
        && d->mAppVersion == other.appVersion()
        && d->mPinStates == other.pinStates()
        && d->mSlot == other.slot()
        && d->mCanLearn == other.canLearnKeys()
        && d->mHasNullPin == other.hasNullPin();
}

bool Card::operator != (const Card& other) const
{
    return !operator==(other);
}

void Card::setErrorMsg(const QString &msg)
{
    d->mErrMsg = msg;
}

QString Card::errorMsg() const
{
    return d->mErrMsg;
}

QString Card::reader() const
{
    return d->mReader;
}
