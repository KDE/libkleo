/*  utils/remarks.cpp

    This file is part of Kleopatra, the KDE keymanager
    Copyright (c) 2019 by g10code GmbH

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

#include "remarks.h"
#include "libkleo_debug.h"

#include <KSharedConfig>
#include <KConfigGroup>
#include <Libkleo/KeyCache>

using namespace Kleo;

bool Remarks::remarksEnabled()
{
    const KConfigGroup conf(KSharedConfig::openConfig(), "RemarkSettings");
    return conf.readEntry("RemarksEnabled", false);
}

void Remarks::enableRemarks(bool enable)
{
    KConfigGroup conf(KSharedConfig::openConfig(), "RemarkSettings");
    conf.writeEntry("RemarksEnabled", enable);
    KeyCache::mutableInstance()->enableRemarks(enable);
}

GpgME::Key Remarks::remarkKey()
{
    const KConfigGroup conf(KSharedConfig::openConfig(), "RemarkSettings");
    const auto remarkKeyFpr = conf.readEntry("RemarkKeyFpr", QString());
    GpgME::Key key;
    if (remarkKeyFpr.isEmpty()) {
        return key;
    }
    key = KeyCache::instance()->findByKeyIDOrFingerprint(remarkKeyFpr.toLatin1().constData());
    if (key.isNull()) {
        qCDebug(LIBKLEO_LOG) << "Failed to find remark key: " << remarkKeyFpr;
        return key;
    }
    return key;
}

std::vector<GpgME::Key> Remarks::remarkKeys()
{
    std::vector<GpgME::Key> ret;
    for (const auto &key: KeyCache::instance()->keys()) {
        if (key.isNull() || key.isRevoked() || key.isExpired() ||
            key.isDisabled() || key.isInvalid() || key.protocol() != GpgME::OpenPGP) {
            continue;
        }
        if (key.ownerTrust() >= GpgME::Key::Full) {
            ret.push_back(key);
        }
    }
    return ret;
}

void Remarks::setRemarkKey(const GpgME::Key &key)
{
    KConfigGroup conf(KSharedConfig::openConfig(), "RemarkSettings");
    conf.writeEntry("RemarkKeyFpr", key.isNull() ? QString() : QString::fromLatin1(key.primaryFingerprint()));
}
