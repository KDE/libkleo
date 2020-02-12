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

#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))

namespace
{
static const char * get_manufacturer (unsigned int no)
{
    switch (no) {
        case 0x0001: return "PPC Card Systems";
        case 0x0002: return "Prism";
        case 0x0003: return "OpenFortress";
        case 0x0004: return "Wewid";
        case 0x0005: return "ZeitControl";
        case 0x0006: return "Yubico";
        case 0x0007: return "OpenKMS";
        case 0x0008: return "LogoEmail";

        case 0x002A: return "Magrathea";

        case 0x1337: return "Warsaw Hackerspace";

        case 0xF517: return "FSIJ";

     /* 0x0000 and 0xFFFF are defined as test cards per spec,
        0xFF00 to 0xFFFE are assigned for use with randomly created
        serial numbers.  */
        case 0x0000:
        case 0xffff: return "test card";
        default: return (no & 0xff00) == 0xff00? "unmanaged S/N range":"unknown";
    }
}

} // namespace

OpenPGPCard::OpenPGPCard()
{
    setAppType(Card::OpenPGPApplication);
}

OpenPGPCard::OpenPGPCard(const std::string &serialno): OpenPGPCard()
{
    setSerialNumber(serialno);
}

std::string OpenPGPCard::sigFpr() const
{
    return mMetaInfo.value("SIGKEY-FPR");
}

std::string OpenPGPCard::encFpr() const
{
    return mMetaInfo.value("ENCKEY-FPR");
}

std::string OpenPGPCard::authFpr() const
{
    return mMetaInfo.value("AUTHKEY-FPR");
}

void OpenPGPCard::setKeyPairInfo(const std::vector< std::pair<std::string, std::string> > &infos)
{
    qCDebug(LIBKLEO_LOG) << "Card" << serialNumber().c_str() << "info:";
    for (const auto &pair: infos) {
        qCDebug(LIBKLEO_LOG) << pair.first.c_str() << ":" << pair.second.c_str();
        if (pair.first == "KEY-FPR" ||
            pair.first == "KEY-TIME") {
            // Key fpr and key time need to be distinguished, the number
            // of the key decides the usage.
            const auto values = QString::fromStdString(pair.second).split(QLatin1Char(' '));
            if (values.size() < 2) {
                qCWarning(LIBKLEO_LOG) << "Invalid entry.";
                setStatus(Card::CardError);
                continue;
            }
            const auto usage = values[0];
            const auto fpr = values[1].toStdString();
            if (usage == QLatin1Char('1')) {
                mMetaInfo.insert(std::string("SIG") + pair.first, fpr);
            } else if (usage == QLatin1Char('2')) {
                mMetaInfo.insert(std::string("ENC") + pair.first, fpr);
            } else if (usage == QLatin1Char('3')) {
                mMetaInfo.insert(std::string("AUTH") + pair.first, fpr);
            } else {
                // Maybe more keyslots in the future?
                qCDebug(LIBKLEO_LOG) << "Unhandled keyslot";
            }
        } else if (pair.first == "KEYPAIRINFO") {
            // Fun, same as above but the other way around.
            const auto values = QString::fromStdString(pair.second).split(QLatin1Char(' '));
            if (values.size() < 2) {
                qCWarning(LIBKLEO_LOG) << "Invalid entry.";
                setStatus(Card::CardError);
                continue;
            }
            const auto usage = values[1];
            const auto grip = values[0].toStdString();
            if (usage == QLatin1String("OPENPGP.1")) {
                mMetaInfo.insert(std::string("SIG") + pair.first, grip);
            } else if (usage == QLatin1String("OPENPGP.2")) {
                mMetaInfo.insert(std::string("ENC") + pair.first, grip);
            } else if (usage == QLatin1String("OPENPGP.3")) {
                mMetaInfo.insert(std::string("AUTH") + pair.first, grip);
            } else {
                // Maybe more keyslots in the future?
                qCDebug(LIBKLEO_LOG) << "Unhandled keyslot";
            }
        } else {
            mMetaInfo.insert(pair.first, pair.second);
        }
    }
}

void OpenPGPCard::setSerialNumber(const std::string &serialno)
{
    char version_buffer[6];
    const char *version = "";
    const char *string = serialno.c_str();

    Card::setSerialNumber(serialno);
    if (strncmp(string, "D27600012401", 12) || strlen(string) != 32 ) {
        /* Not a proper OpenPGP card serialnumber.  Display the full
           serialnumber. */
        mManufacturer = "unknown";
    } else {
        /* Reformat the version number to be better human readable.  */
        char *p = version_buffer;
        if (string[12] != '0') {
            *p++ = string[12];
        }
        *p++ = string[13];
        *p++ = '.';
        if (string[14] != '0') {
            *p++ = string[14];
        }
        *p++ = string[15];
        *p++ = '\0';
        version = version_buffer;

        /* Get the manufacturer.  */
        mManufacturer = get_manufacturer(xtoi_2(string + 16)*256 + xtoi_2(string + 18));
    }

    mIsV2 = !((*version == '1' || *version == '0') && version[1] == '.');
    mCardVersion = version;
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

std::string OpenPGPCard::manufacturer() const
{
    return mManufacturer;
}

std::string OpenPGPCard::cardVersion() const
{
    return mCardVersion;
}

std::string OpenPGPCard::cardHolder() const
{
    auto list = QString::fromStdString(mMetaInfo.value("DISP-NAME")).split(QStringLiteral("<<"));
    std::reverse(list.begin(), list.end());
    return list.join(QLatin1Char(' ')).toStdString();
}

std::string OpenPGPCard::pubkeyUrl() const
{
    return mMetaInfo.value("PUBKEY-URL");
}
