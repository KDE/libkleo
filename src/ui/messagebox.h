/*
    messagebox.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <KMessageBox>

#undef MessageBox // Windows

class QString;
class QWidget;

namespace GpgME
{
class SigningResult;
class EncryptionResult;
}

namespace QGpgME
{
class Job;
}

namespace Kleo
{
class AuditLogEntry;

namespace MessageBox
{

KLEO_EXPORT
void information(QWidget *parent,
                 const QString &text,
                 const Kleo::AuditLogEntry &auditLog,
                 const QString &title = {},
                 KMessageBox::Options options = KMessageBox::Notify);

KLEO_EXPORT
void error(QWidget *parent,
           const QString &text,
           const Kleo::AuditLogEntry &auditLog,
           const QString &title = {},
           KMessageBox::Options options = KMessageBox::Notify);

KLEO_EXPORT
KLEO_DEPRECATED_VERSION(5, 23, "Use AuditLogViewer::showAuditLog()")
void auditLog(QWidget *parent, const QString &log, const QString &title = {});

}
}
