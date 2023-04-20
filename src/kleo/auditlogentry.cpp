/* -*- mode: c++; c-basic-offset:4 -*-
    kleo/auditlogentry.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "auditlogentry.h"

#include <libkleo/formatting.h>
#include <libkleo_debug.h>

#include <QGpgME/Job>

#include <QUrl>
#include <QUrlQuery>

#include <gpgme++/error.h>

using namespace Kleo;

class AuditLogEntry::Private
{
public:
    QString text;
    GpgME::Error error;
};

AuditLogEntry::AuditLogEntry()
    : AuditLogEntry{QString{}, GpgME::Error{}}
{
}

AuditLogEntry::AuditLogEntry(const GpgME::Error &error)
    : AuditLogEntry{QString{}, error}
{
}

AuditLogEntry::AuditLogEntry(const QString &text, const GpgME::Error &error)
    : d{new Private{text, error}}
{
}

AuditLogEntry::~AuditLogEntry() = default;

AuditLogEntry::AuditLogEntry(const AuditLogEntry &other)
    : d{new Private{*other.d}}
{
}

AuditLogEntry &AuditLogEntry::operator=(const AuditLogEntry &other)
{
    *d = *other.d;
    return *this;
}

AuditLogEntry::AuditLogEntry(AuditLogEntry &&other) = default;
AuditLogEntry &AuditLogEntry::operator=(AuditLogEntry &&other) = default;

AuditLogEntry AuditLogEntry::fromJob(const QGpgME::Job *job)
{
    if (job) {
        return AuditLogEntry{job->auditLogAsHtml(), job->auditLogError()};
    } else {
        return AuditLogEntry{};
    }
}

GpgME::Error AuditLogEntry::error() const
{
    return d->error;
}

QString AuditLogEntry::text() const
{
    return d->text;
}

QUrl AuditLogEntry::asUrl(const QUrl &urlTemplate) const
{
    // more or less the same as
    // kmail/objecttreeparser.cpp:makeShowAuditLogLink(), so any bug
    // fixed here equally applies there:
    if (const int code = d->error.code()) {
        if (code == GPG_ERR_NOT_IMPLEMENTED) {
            qCDebug(LIBKLEO_LOG) << "not showing link (not implemented)";
        } else if (code == GPG_ERR_NO_DATA) {
            qCDebug(LIBKLEO_LOG) << "not showing link (not available)";
        } else {
            qCDebug(LIBKLEO_LOG) << "Error Retrieving Audit Log:" << Formatting::errorAsString(d->error);
        }
        return {};
    }

    if (d->text.isEmpty()) {
        return {};
    }

    QUrl url = urlTemplate;
    QUrlQuery urlQuery{url};
    urlQuery.addQueryItem(QStringLiteral("log"), d->text);
    url.setQuery(urlQuery);
    return url;
}

QDebug operator<<(QDebug debug, const AuditLogEntry &auditLog)
{
    const bool oldSetting = debug.autoInsertSpaces();
    debug.nospace() << "AuditLogEntry(" << Formatting::errorAsString(auditLog.error()) << ", " << auditLog.text() << ')';
    debug.setAutoInsertSpaces(oldSetting);
    return debug.maybeSpace();
}
