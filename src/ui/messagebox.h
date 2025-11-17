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
void informationWId(WId parentId,
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
void errorWId(WId parentId,
              const QString &text,
              const Kleo::AuditLogEntry &auditLog,
              const QString &title = {},
              KMessageBox::Options options = KMessageBox::Notify);

/*!
 * Creates and shows a message dialog with a button to show the audit log.
 *
 * You must connect to the finished() signal to know when the dialog is closed.
 * The result of the finished() signal is the button code (QDialogButtonBox::StandardButton)
 * of the clicked button.
 *
 * The button to show the audit log is only shown if an audit log is available
 * and not empty.
 */
KLEO_EXPORT
QDialog *create(QWidget *parent,
                QDialogButtonBox::StandardButtons buttons,
                QMessageBox::Icon icon,
                const QString &text,
                const Kleo::AuditLogEntry &auditLog,
                const QString &title = {},
                KMessageBox::Options options = KMessageBox::Notify);
}
}
