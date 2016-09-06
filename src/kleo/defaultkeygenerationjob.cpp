/*  This file is part of Kleopatra, the KDE keymanager
    Copyright (c) 2016 Klarälvdalens Datakonsult AB

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
*/

#include "defaultkeygenerationjob.h"
#include "kleo/cryptobackendfactory.h"
#include "kleo/keygenerationjob.h"

#include <QPointer>
#include <QEvent>

using namespace Kleo;

namespace Kleo {

class DefaultKeyGenerationJob::Private
{
public:
    Private()
    {}

    ~Private()
    {
        if (job) {
            job->deleteLater();
        }
    }

    QPointer<KeyGenerationJob> job;
};
}


DefaultKeyGenerationJob::DefaultKeyGenerationJob(QObject* parent)
    : Job(parent)
    , d(new DefaultKeyGenerationJob::Private())
{
}

DefaultKeyGenerationJob::~DefaultKeyGenerationJob()
{
    delete d;
}

QString DefaultKeyGenerationJob::auditLogAsHtml() const
{
    return d->job ? d->job->auditLogAsHtml() : QString();
}

GpgME::Error DefaultKeyGenerationJob::auditLogError() const
{
    return d->job ? d->job->auditLogError() : GpgME::Error();
}

void DefaultKeyGenerationJob::slotCancel()
{
    if (d->job) {
        d->job->slotCancel();
    }
}

GpgME::Error DefaultKeyGenerationJob::start(const QString &email, const QString &name)
{
    const QString args = QStringLiteral("<GnupgKeyParms format=\"internal\">\n"
                                        "%ask-passphrase\n"
                                        "key-type:      RSA\n"
                                        "key-length:    2048\n"
                                        "key-usage:     sign\n"
                                        "subkey-type:   RSA\n"
                                        "subkey-length: 2048\n"
                                        "subkey-usage:  encrypt\n"
                                        "name-email:    %1\n"
                                        "name-real:     %2\n"
                                        "</GnupgKeyParms>").arg(email, name);

    d->job = CryptoBackendFactory::instance()->openpgp()->keyGenerationJob();
    d->job->installEventFilter(this);
    connect(d->job.data(), &KeyGenerationJob::result,
            this, &DefaultKeyGenerationJob::result);
    connect(d->job.data(), &KeyGenerationJob::done,
            this, &DefaultKeyGenerationJob::done);
    connect(d->job.data(), &KeyGenerationJob::done,
            this, &QObject::deleteLater);
    return d->job->start(args);
}

bool DefaultKeyGenerationJob::eventFilter(QObject *watched, QEvent *event)
{
    // Intercept the KeyGenerationJob's deferred delete event. We want the job
    // to live at least as long as we do so we can delegate calls to it. We will
    // delete the job manually afterwards.
    if (watched == d->job && event->type() == QEvent::DeferredDelete) {
        return true;
    }

    return Job::eventFilter(watched, event);
}
