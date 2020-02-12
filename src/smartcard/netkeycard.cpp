/*  smartcard/netkeycard.cpp

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

#include "netkeycard.h"

#include "libkleo_debug.h"

#include <gpgme++/error.h>
#include <gpgme++/context.h>
#include <gpgme++/keylistresult.h>

#include <memory>
#include <string>

using namespace Kleo;
using namespace Kleo::SmartCard;

namespace
{
static std::string parse_keypairinfo(const std::string &kpi)
{
    static const char hexchars[] = "0123456789abcdefABCDEF";
    return '&' + kpi.substr(0, kpi.find_first_not_of(hexchars));
}

static GpgME::Key parse_keypairinfo_and_lookup_key(GpgME::Context *ctx, const std::string &kpi)
{
    if (!ctx) {
        return GpgME::Key();
    }
    const std::string pattern = parse_keypairinfo(kpi);
    qCDebug(LIBKLEO_LOG) << "parse_keypairinfo_and_lookup_key: pattern=" << pattern.c_str();
    if (const auto err = ctx->startKeyListing(pattern.c_str())) {
        qCDebug(LIBKLEO_LOG) << "parse_keypairinfo_and_lookup_key: startKeyListing failed:" << err.asString();
        return GpgME::Key();
    }
    GpgME::Error e;
    const auto key = ctx->nextKey(e);
    ctx->endKeyListing();
    qCDebug(LIBKLEO_LOG) << "parse_keypairinfo_and_lookup_key: e=" << e.code() << "; key.isNull()" << key.isNull();
    return key;
}

} // namespace

NetKeyCard::NetKeyCard()
{
    setAppType(Card::NksApplication);
}

void NetKeyCard::setKeyPairInfo(const std::vector<std::string> &infos)
{
    // check that any of the keys are new
    const std::unique_ptr<GpgME::Context> klc(GpgME::Context::createForProtocol(GpgME::CMS));
    if (!klc.get()) {
        return;
    }
    klc->setKeyListMode(GpgME::Ephemeral);
    klc->addKeyListMode(GpgME::Validate);

    setCanLearnKeys(false);
    mKeys.clear();
    for (const auto &info: infos) {
        const auto key = parse_keypairinfo_and_lookup_key(klc.get(), info);
        if (key.isNull()) {
            setCanLearnKeys(true);
        }
        mKeys.push_back(key);
    }
}


// State 0 -> NKS PIN Retry counter
// State 1 -> NKS PUK Retry counter
// State 2 -> SigG PIN Retry counter
// State 3 -> SigG PUK Retry counter

bool NetKeyCard::hasNKSNullPin() const
{
    const auto states = pinStates();
    if (states.size() < 2) {
        qCWarning(LIBKLEO_LOG) << "Invalid size of pin states:" << states.size();
        return false;
    }
    return states[0] == Card::NullPin;
}

bool NetKeyCard::hasSigGNullPin() const
{
    const auto states = pinStates();
    if (states.size() < 4) {
        qCWarning(LIBKLEO_LOG) << "Invalid size of pin states:" << states.size();
        return false;
    }
    return states[2] == Card::NullPin;
}

std::vector<GpgME::Key> NetKeyCard::keys() const
{
    return mKeys;
}
