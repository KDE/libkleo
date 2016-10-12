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

#include <qgpgme/protocol.h>
#include <qgpgme/keygenerationjob.h>

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

    QString passphrase;
    QPointer<QGpgME::KeyGenerationJob> job;
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

void DefaultKeyGenerationJob::setPassphrase(const QString &passphrase)
{
    // null QString = ask for passphrase
    // empty QString = empty passphrase
    // non-empty QString = passphrase
    d->passphrase = passphrase.isNull() ? QLatin1String("") : passphrase;
}

GpgME::Error DefaultKeyGenerationJob::start(const QString &email, const QString &name)
{
    const QString passphrase = d->passphrase.isNull() ? QStringLiteral("%ask-passphrase") :
                               d->passphrase.isEmpty() ? QStringLiteral("%no-protection") :
                                                         QStringLiteral("passphrase:    %1").arg(d->passphrase);

    const QString args = QStringLiteral("<GnupgKeyParms format=\"internal\">\n"
                                        "key-type:      RSA\n"
                                        "key-length:    2048\n"
                                        "key-usage:     sign\n"
                                        "subkey-type:   RSA\n"
                                        "subkey-length: 2048\n"
                                        "subkey-usage:  encrypt\n"
                                        "%1\n"
                                        "name-email:    %2\n"
                                        "name-real:     %3\n"
                                        "</GnupgKeyParms>").arg(passphrase, email, name);

    d->job = QGpgME::openpgp()->keyGenerationJob();
    d->job->installEventFilter(this);
    connect(d->job.data(), &QGpgME::KeyGenerationJob::result, this, &DefaultKeyGenerationJob::result);
    connect(d->job.data(), &QGpgME::KeyGenerationJob::done, this, &DefaultKeyGenerationJob::done);
    connect(d->job.data(), &QGpgME::KeyGenerationJob::done, this, &QObject::deleteLater);
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
