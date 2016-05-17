/*
    qgpgmekeyformailboxjob.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    Copyright (c) 2016 Intevation GmbH

    Libkleopatra is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    Libkleopatra is distributed in the hope that it will be useful,
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

#include "qgpgmekeyformailboxjob.h"
#include "qgpgmekeylistjob.h"

using namespace Kleo;
using namespace GpgME;
using namespace boost;

QGpgMEKeyForMailboxJob::QGpgMEKeyForMailboxJob(Context *context)
    : mixin_type(context)
{
    lateInitialization();
}

QGpgMEKeyForMailboxJob::~QGpgMEKeyForMailboxJob() {}

static QGpgMEKeyForMailboxJob::result_type do_work(Context *ctx, const QString &mailbox, bool canEncrypt)
{
    /* Do a Keylisting. */
    ctx->setKeyListMode(GpgME::Extern | GpgME::Local | GpgME::Signatures | GpgME::Validate);
    std::vector<Key> keys;
    QGpgMEKeyListJob *keylist = new QGpgMEKeyListJob(ctx);

    KeyListResult result = keylist->exec(QStringList() << mailbox, false, keys);

    if (result.error()) {
        return make_tuple(result, Key(), UserID(), QString(), Error());
    }

    Key kCandidate;
    UserID uidCandidate;
    Q_FOREACH (const Key k, keys) {
        if (canEncrypt && !k.canEncrypt()) {
            continue;
        }
        /* First get the uid that matches the mailbox */
        Q_FOREACH (const UserID u, k.userIDs()) {
            if (QString::fromUtf8(u.email()).toLower() == mailbox.toLower()) {
                if (uidCandidate.isNull() ||
                    (kCandidate.isExpired() && !k.isExpired()) ||
                    (kCandidate.isRevoked() && !k.isRevoked()) ||
                    (kCandidate.isInvalid() && !k.isInvalid()) ||
                    (kCandidate.isDisabled() && !k.isDisabled()) ||
                    (uidCandidate.isRevoked() && !u.isRevoked()) ||
                    (uidCandidate.isInvalid() && !u.isInvalid()) ||
                    uidCandidate.validity() < u.validity()) {
                    /* Validity of the new key is better. */
                    uidCandidate = u;
                    kCandidate = k;
                } else if (uidCandidate.validity() == u.validity() &&
                           !k.isExpired() && !k.isRevoked() &&
                           !k.isInvalid() && !k.isDisabled() &&
                           !u.isRevoked() && !u.isInvalid()) {
                    /* Both are the same check which one is newer. */
                    time_t oldTime = 0;
                    Q_FOREACH (const Subkey s, kCandidate.subkeys()) {
                        if ((canEncrypt && s.canEncrypt()) && !s.isExpired() && !s.isRevoked() &&
                            !s.isDisabled() && !s.isInvalid()) {
                            oldTime = s.creationTime();
                        }
                    }
                    time_t newTime = 0;
                    Q_FOREACH (const Subkey s, k.subkeys()) {
                        if ((canEncrypt && s.canEncrypt()) && !s.isExpired() &&
                            !s.isRevoked() && !s.isDisabled() &&
                            !s.isInvalid()) {
                            newTime = s.creationTime();
                        }
                    }
                    if (newTime > oldTime) {
                        uidCandidate = u;
                        kCandidate = k;
                    }
                }
            }
        }
    }
    return make_tuple(result, kCandidate, uidCandidate, QString(), Error());
}

Error QGpgMEKeyForMailboxJob::start(const QString &mailbox, bool canEncrypt)
{
    run(bind(&do_work, _1, mailbox, canEncrypt));
    return Error();
}

KeyListResult QGpgMEKeyForMailboxJob::exec(const QString &mailbox, bool canEncrypt, Key &key, UserID &uid)
{
    const result_type r = do_work(context(), mailbox, canEncrypt);
    resultHook(r);
    key = get<1>(r);
    uid = get<2>(r);
    return get<0>(r);
}
