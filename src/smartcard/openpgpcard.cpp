/*  smartcard/openpgpcard.cpp

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

/* Code in this file is partly based on the GNU Privacy Assistant
 * (cm-openpgp.c) git rev. 0a78795146661234070681737b3e08228616441f
 *
 * Whis is:
 * Copyright (C) 2008, 2009 g10 Code GmbH
 *
 * And may be licensed under the GNU General Public License
 * as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 */

#include "openpgpcard.h"

#include "libkleo_debug.h"


using namespace Kleo;
using namespace Kleo::SmartCard;


class OpenPGPCard::Private
{
public:
    Private (): mIsV2(false)
    {

    }

    bool mIsV2 = false;
    std::string mCardVersion;
    std::string mManufacturer;
};

OpenPGPCard::OpenPGPCard(const QString &std_out):
    Card(std_out, Card::OpenPGPApplication),
    d(new Private())
{
}

const QString OpenPGPCard::sigFpr() const
{
    return QString();
}

const QString OpenPGPCard::encFpr() const
{
    return QString();
}

const QString OpenPGPCard::authFpr() const
{
    return QString();
}

bool OpenPGPCard::operator == (const Card& rhs) const
{
    const OpenPGPCard *other = dynamic_cast<const OpenPGPCard *>(&rhs);
    if (!other) {
        return false;
    }

    return Card::operator ==(rhs)
        && sigFpr() == other->sigFpr()
        && encFpr() == other->encFpr()
        && authFpr() == other->authFpr()
        && manufacturer() == other->manufacturer()
        && cardVersion() == other->cardVersion()
        && cardHolder() == other->cardHolder()
        && pubkeyUrl() == other->pubkeyUrl();
}

const QString OpenPGPCard::manufacturer() const
{
    return getSingleProperty("Manufacturer");
}

const QString OpenPGPCard::cardVersion() const
{
    return getSingleProperty("Version");
}

const QString OpenPGPCard::cardHolder() const
{
    return getSingleProperty("Name of cardholder");
}

const QString OpenPGPCard::pubkeyUrl() const
{
    return getSingleProperty("URL of public key");
}
