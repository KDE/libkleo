/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <memory>

class QDebug;
class QString;
class QUrl;

namespace GpgME
{
class Error;
}
namespace QGpgME
{
class Job;
}

namespace Kleo
{

class KLEO_EXPORT AuditLogEntry
{
public:
    AuditLogEntry();
    explicit AuditLogEntry(const GpgME::Error &error);
    AuditLogEntry(const QString &text, const GpgME::Error &error);
    ~AuditLogEntry();

    AuditLogEntry(const AuditLogEntry &other);
    AuditLogEntry &operator=(const AuditLogEntry &other);

    AuditLogEntry(AuditLogEntry &&other);
    AuditLogEntry &operator=(AuditLogEntry &&other);

    static AuditLogEntry fromJob(const QGpgME::Job *);

    GpgME::Error error() const;
    QString text() const;

    QUrl asUrl(const QUrl &urlTemplate) const;

private:
    class Private;
    std::unique_ptr<Private> d;
};

}

KLEO_EXPORT QDebug operator<<(QDebug debug, const Kleo::AuditLogEntry &auditLog);
