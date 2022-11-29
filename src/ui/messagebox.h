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

namespace GpgME
{
class SigningResult;
class EncryptionResult;
}

namespace QGpgME
{
class Job;
}

class QWidget;
class QString;

namespace Kleo
{
namespace MessageBox
{

KLEO_EXPORT
void information(QWidget *parent,
                 const GpgME::SigningResult &result,
                 const QGpgME::Job *job,
                 const QString &caption,
                 KMessageBox::Options options = KMessageBox::Notify);

KLEO_EXPORT
void information(QWidget *parent, const GpgME::SigningResult &result, const QGpgME::Job *job, KMessageBox::Options options = KMessageBox::Notify);

KLEO_EXPORT
void error(QWidget *parent,
           const GpgME::SigningResult &result,
           const QGpgME::Job *job,
           const QString &caption,
           KMessageBox::Options options = KMessageBox::Notify);

KLEO_EXPORT
void error(QWidget *parent, const GpgME::SigningResult &result, const QGpgME::Job *job, KMessageBox::Options options = KMessageBox::Notify);

KLEO_EXPORT
void information(QWidget *parent,
                 const GpgME::EncryptionResult &result,
                 const QGpgME::Job *job,
                 const QString &caption,
                 KMessageBox::Options options = KMessageBox::Notify);
KLEO_EXPORT
void information(QWidget *parent, const GpgME::EncryptionResult &result, const QGpgME::Job *job, KMessageBox::Options options = KMessageBox::Notify);

KLEO_EXPORT
void error(QWidget *parent,
           const GpgME::EncryptionResult &result,
           const QGpgME::Job *job,
           const QString &caption,
           KMessageBox::Options options = KMessageBox::Notify);

KLEO_EXPORT
void error(QWidget *parent, const GpgME::EncryptionResult &result, const QGpgME::Job *job, KMessageBox::Options options = KMessageBox::Notify);

KLEO_EXPORT
void information(QWidget *parent,
                 const GpgME::SigningResult &sresult,
                 const GpgME::EncryptionResult &eresult,
                 const QGpgME::Job *job,
                 const QString &caption,
                 KMessageBox::Options options = KMessageBox::Notify);

KLEO_EXPORT
void information(QWidget *parent,
                 const GpgME::SigningResult &sresult,
                 const GpgME::EncryptionResult &eresult,
                 const QGpgME::Job *job,
                 KMessageBox::Options options = KMessageBox::Notify);

KLEO_EXPORT
void error(QWidget *parent,
           const GpgME::SigningResult &sresult,
           const GpgME::EncryptionResult &eresult,
           const QGpgME::Job *job,
           const QString &caption,
           KMessageBox::Options options = KMessageBox::Notify);

KLEO_EXPORT
void error(QWidget *parent,
           const GpgME::SigningResult &sresult,
           const GpgME::EncryptionResult &eresult,
           const QGpgME::Job *job,
           KMessageBox::Options options = KMessageBox::Notify);

KLEO_EXPORT
KLEO_DEPRECATED_VERSION(5, 23, "Use AuditLogViewer::showAuditLog()")
void auditLog(QWidget *parent, const QGpgME::Job *job, const QString &caption);

KLEO_EXPORT
KLEO_DEPRECATED_VERSION(5, 23, "Use AuditLogViewer::showAuditLog()")
void auditLog(QWidget *parent, const QGpgME::Job *job);

KLEO_EXPORT
KLEO_DEPRECATED_VERSION(5, 23, "Use AuditLogViewer::showAuditLog()")
void auditLog(QWidget *parent, const QString &log, const QString &caption);

KLEO_EXPORT
KLEO_DEPRECATED_VERSION(5, 23, "Use AuditLogViewer::showAuditLog()")
void auditLog(QWidget *parent, const QString &log);

KLEO_EXPORT
bool showAuditLogButton(const QGpgME::Job *job);

}
}
