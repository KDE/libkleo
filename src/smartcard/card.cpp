/*  smartcard/card.cpp

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
    Private(const QString &gpgOutput, AppType type):
        mCanLearn(false),
        mHasNullPin(false),
        mStatus(Status::NoCard),
        mAppType(UnknownApplication)
    {
        mAppType = type;
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
    }

    const QStringList getProperties(const char *val) const
    {
        return mProperties[QLatin1String(val)];
    }

    const QString getSingleProperty(const char *val) const
    {
        const auto &list = mProperties[QLatin1String(val)];
        if (list.empty()) {
            return QString();
        }
        return list.first();
    }

    bool mCanLearn;
    bool mHasNullPin;
    Card::Status mStatus;
    AppType mAppType;
    std::vector<PinState> mPinStates;
    int mSlot;
    QString mErrMsg;
    QMap<QString, QStringList> mProperties;
};

Card::Card(const QString &gpgOutput, AppType type): d(new Private(gpgOutput, type))
{
}

const QString Card::getSingleProperty(const char *propName) const
{
    return d->getSingleProperty(propName);
}

const QStringList Card::getProperties(const char *propName) const
{
    return d->getProperties(propName);
}

Card::Status Card::status() const
{
    return d->mStatus;
}

const QString Card::serialNumber() const
{
    return getSingleProperty("Serial number");
}

Card::AppType Card::appType() const
{
    return d->mAppType;
}

const QString Card::appVersion() const
{
    return getSingleProperty("Version");
}

std::vector<Card::PinState> Card::pinStates() const
{
    return d->mPinStates;
}

int Card::slot() const
{
    return d->mSlot;
}

bool Card::hasNullPin() const
{
    return d->mHasNullPin;
}

bool Card::canLearnKeys() const
{
    return d->mCanLearn;
}

bool Card::operator == (const Card& other) const
{
    return d->mProperties == other.properties();
}

bool Card::operator != (const Card& other) const
{
    return !operator==(other);
}

QString Card::errorMsg() const
{
    return d->getSingleProperty("Error");
}

QString Card::reader() const
{
    return d->getSingleProperty("Reader");
}

const QMap <QString, QStringList> Card::properties() const
{
    return d->mProperties;
}
