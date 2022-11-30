/*
    messagebox.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "messagebox.h"

#include "auditlogviewer.h"

#include <kleo/auditlogentry.h>

#include <kleo_ui_debug.h>

#include <KGuiItem>
#include <KLocalizedString>
#include <KSharedConfig>

#include <QGpgME/Job>

#include <QDialog>
#include <QDialogButtonBox>
#include <QPushButton>

#include <gpgme++/encryptionresult.h>
#include <gpgme++/signingresult.h>

#include <gpg-error.h>

using namespace Kleo;
using namespace GpgME;
using namespace QGpgME;

namespace
{
bool showAuditLogButton(const AuditLogEntry &auditLog)
{
    if (auditLog.error().code() == GPG_ERR_NOT_IMPLEMENTED) {
        qCDebug(KLEO_UI_LOG) << "not showing audit log button (not supported)";
        return false;
    }
    if (auditLog.error().code() == GPG_ERR_NO_DATA) {
        qCDebug(KLEO_UI_LOG) << "not showing audit log button (GPG_ERR_NO_DATA)";
        return false;
    }
    if (!auditLog.error() && auditLog.text().isEmpty()) {
        qCDebug(KLEO_UI_LOG) << "not showing audit log button (success, but result empty)";
        return false;
    }
    return true;
}

void showMessageBox(QWidget *parent,
                    QMessageBox::Icon icon,
                    const QString &text,
                    const AuditLogEntry &auditLog,
                    const QString &caption,
                    KMessageBox::Options options)
{
    QDialog *dialog = new QDialog(parent);
    dialog->setWindowTitle(caption);
    QDialogButtonBox *box = new QDialogButtonBox(showAuditLogButton(auditLog) ? (QDialogButtonBox::Yes | QDialogButtonBox::No) : QDialogButtonBox::Yes, parent);
    QPushButton *yesButton = box->button(QDialogButtonBox::Yes);
    yesButton->setDefault(true);
    dialog->setObjectName(QStringLiteral("error"));
    dialog->setModal(true);
    KGuiItem::assign(yesButton, KStandardGuiItem::ok());
    KGuiItem::assign(box->button(QDialogButtonBox::No), KGuiItem(i18n("&Show Audit Log")));

    if (QDialogButtonBox::No == KMessageBox::createKMessageBox(dialog, box, icon, text, QStringList(), QString(), nullptr, options)) {
        AuditLogViewer::showAuditLog(parent, auditLog);
    }
}
}

void MessageBox::auditLog(QWidget *parent, const Job *job, const QString &caption)
{
    if (!job) {
        return;
    }
    AuditLogViewer::showAuditLog(parent, AuditLogEntry::fromJob(job), caption);
}

void MessageBox::auditLog(QWidget *parent, const QString &log, const QString &caption)
{
    AuditLogViewer::showAuditLog(parent, AuditLogEntry{log, Error{}}, caption);
}

void MessageBox::auditLog(QWidget *parent, const Job *job)
{
    if (!job) {
        return;
    }
    AuditLogViewer::showAuditLog(parent, AuditLogEntry::fromJob(job));
}

void MessageBox::auditLog(QWidget *parent, const QString &log)
{
    AuditLogViewer::showAuditLog(parent, AuditLogEntry{log, Error{}});
}
