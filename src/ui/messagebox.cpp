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
                    const QString &title,
                    KMessageBox::Options options)
{
    if (showAuditLogButton(auditLog)) {
        QDialog *dialog = new QDialog{parent};
        dialog->setWindowTitle(title);
        QDialogButtonBox *box = new QDialogButtonBox(QDialogButtonBox::Yes | QDialogButtonBox::No, dialog);
        KGuiItem::assign(box->button(QDialogButtonBox::Yes), KGuiItem{i18nc("@action:button", "Show Audit Log")});
        KGuiItem::assign(box->button(QDialogButtonBox::No), KStandardGuiItem::ok());

        if (options & KMessageBox::WindowModal) {
            dialog->setWindowModality(Qt::WindowModal);
        }
        dialog->setModal(true);

        // Flag as Dangerous to make the Ok button the default button
        const auto choice = KMessageBox::createKMessageBox(dialog, box, icon, text, QStringList{}, QString{}, nullptr, options | KMessageBox::Dangerous);
        if (choice == QDialogButtonBox::Yes) {
            AuditLogViewer::showAuditLog(parent, auditLog);
        }
    } else {
        const auto dialogType = (icon == QMessageBox::Information) ? KMessageBox::Information : KMessageBox::Error;
        KMessageBox::messageBox(parent, dialogType, text, title, {}, {}, {}, QString{}, options);
    }
}
}

void MessageBox::information(QWidget *parent, const QString &text, const Kleo::AuditLogEntry &auditLog, const QString &title, KMessageBox::Options options)
{
    showMessageBox(parent, QMessageBox::Information, text, auditLog, title.isEmpty() ? i18nc("@title:window", "Information") : title, options);
}

void MessageBox::error(QWidget *parent, const QString &text, const Kleo::AuditLogEntry &auditLog, const QString &title, KMessageBox::Options options)
{
    showMessageBox(parent, QMessageBox::Critical, text, auditLog, title.isEmpty() ? i18nc("@title:window", "Error") : title, options);
}

void MessageBox::auditLog(QWidget *parent, const QString &log, const QString &title)
{
    AuditLogViewer::showAuditLog(parent, AuditLogEntry{log, Error{}}, title);
}
