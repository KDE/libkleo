/*
    This file is part of libkleopatra, the KDE keymanagement library
    Copyright (c) 2020 g10 Code GmbH

    Libkleopatra is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    Libkleopatra is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

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

#include "cardmanager.h"

#include "libkleo_debug.h"

#include <gpgme++/gpgmepp_version.h>

#include <QGpgME/Protocol>

#if GPGMEPP_VERSION < 0x10E00 // 1.14.0
# define GPGMEPP_TOO_OLD
#else
# include <QGpgME/GpgCardJob>
#endif

using namespace Kleo;
using namespace SmartCard;

static CardManager *s_instance = nullptr;

class CardManager::Private
{
public:
    Private(CardManager *qq): q(qq), mErrCode(0)
    {

    }

    void addCard(const QString &std_out)
    {
        Card *genericCard = new Card(std_out);
        /* TODO Specialize */

        mCards << std::shared_ptr<Card>(genericCard);
    }

    void cardListDone (const QString &std_out, const QString &std_err,
                       int exitCode)
    {
        mErrorStr = std_err;
        mErrCode = exitCode;
        mCards.clear();
        if (exitCode) {
            qCDebug(LIBKLEO_LOG) << "Card list failed with code:" << exitCode;
            Q_EMIT q->cardsMayHaveChanged ();
            return;
        }

        mCardsToApps.clear();
        const auto lines = std_out.split(QRegExp("[\r\n]"),
                                         QString::SkipEmptyParts);
        for (const auto &line: lines) {
            auto words = line.split(QLatin1Char(' '));
             /* The first word is the selection */
            words.pop_front ();
            const auto key = words.takeFirst();
            mCardsToApps.insert(key, words);
        }
        int i = 0;
        for (const auto &id: mCardsToApps.keys()) {
            const auto apps = mCardsToApps.value(id);

            /* Now for each card start a specific listing */
            auto cmd = QGpgME::gpgCardJob();
            QString std_out;
            QString std_err;
            int exitCode = 0;

            if (apps.empty()) {
                GpgME::Error err = cmd->exec(QStringList() << QStringLiteral("--")
                                                           << QStringLiteral("list")
                                                           << QStringLiteral("--no-key-lookup")
                                                           << QString::number(i), std_out, std_err,
                                                           exitCode);
                if (err || exitCode) {
                    qCDebug(LIBKLEO_LOG) << "Card list failed with code:" << exitCode;
                    qCDebug(LIBKLEO_LOG) << "Error:" << std_err;
                } else {
                    addCard(std_out);
                }
            } else {
                for (const auto &app: apps) {
                    GpgME::Error err = cmd->exec(QStringList() << QStringLiteral("--")
                            << QStringLiteral("list")
                            << QStringLiteral("--no-key-lookup")
                            << QString::number(i)
                            << app,
                            std_out, std_err,
                            exitCode);
                    if (err || exitCode) {
                        qCDebug(LIBKLEO_LOG) << "Card list failed with code:" << exitCode;
                        qCDebug(LIBKLEO_LOG) << "Error:" << std_err;
                    } else {
                        addCard(std_out);
                    }
                }
            }
            i++;
        }
        Q_EMIT q->cardsMayHaveChanged ();
    }

    QList<std::shared_ptr<Card> > mCards;

private:
    /* A map of available card ID's to the apps they support */
    QMap<QString, QStringList> mCardsToApps;
    CardManager *q;
    QString mErrorStr;
    int mErrCode;
};

CardManager::CardManager(): d(new Private(this))
{
}

CardManager::~CardManager()
{
    s_instance = nullptr;
}

void CardManager::startCardList() const
{
#ifdef GPGMEPP_TOO_OLD
    qCWarning(LIBKLEO_LOG) << "GPGME Version too old";
    return;
#else
    auto cmd = QGpgME::gpgCardJob();

    connect(cmd, &QGpgME::GpgCardJob::result, this,
            [this] (const QString &std_out, const QString &std_err, int exitCode, const QString&, const GpgME::Error &) {
        d->cardListDone(std_out, std_err, exitCode);
    });

    cmd->start(QStringList() << QStringLiteral("--")
                             << QStringLiteral("list")
                             << QStringLiteral("--cards")
                             << QStringLiteral("--apps"));
#endif
}

QList <std::shared_ptr<Card> > CardManager::cards() const
{
    return d->mCards;
}

/* static */
CardManager *CardManager::instance()
{
    if (s_instance) {
        return s_instance;
    }
    s_instance = new CardManager();
    return s_instance;
}
