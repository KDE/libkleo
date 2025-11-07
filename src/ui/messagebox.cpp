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
#include <QWindow>

#include <gpgme++/encryptionresult.h>
#include <gpgme++/signingresult.h>

#include <gpg-error.h>

using namespace Kleo;
using namespace GpgME;
using namespace QGpgME;

/* copied from kmessagebox.cpp in KWidgetAddons */
static void setMainWindow(QWidget *subWidget, WId mainWindowId)
{
#ifdef Q_OS_OSX
    if (!QWidget::find(mainWindowId)) {
        return;
    }
#endif
    // Set the WA_NativeWindow attribute to force the creation of the QWindow.
    // Without this QWidget::windowHandle() returns 0.
    subWidget->setAttribute(Qt::WA_NativeWindow, true);
    QWindow *subWindow = subWidget->windowHandle();
    Q_ASSERT(subWindow);

    QWindow *mainWindow = QWindow::fromWinId(mainWindowId);
    if (!mainWindow) {
        // foreign windows not supported on all platforms
        return;
    }
    // mainWindow is not the child of any object, so make sure it gets deleted at some point
    QObject::connect(subWidget, &QObject::destroyed, mainWindow, &QObject::deleteLater);
    subWindow->setTransientParent(mainWindow);
}

/* copied from kmessagebox.cpp in KWidgetAddons */
static QDialog *createWIdDialog(WId parent_id)
{
    QWidget *parent = QWidget::find(parent_id);
    QDialog *dialog = new QDialog(parent, Qt::Dialog);
    if (!parent && parent_id) {
        setMainWindow(dialog, parent_id);
    }
    return dialog;
}

static bool showAuditLogButton(const AuditLogEntry &auditLog)
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

static void showMessageBoxWithAuditLogButton(QDialog *dialog,
                                             QMessageBox::Icon icon,
                                             const QString &text,
                                             const AuditLogEntry &auditLog,
                                             const QString &title,
                                             KMessageBox::Options options)
{
    const QString auditLogButtonText = (icon == QMessageBox::Critical //
                                            ? i18nc("@action:button", "Diagnostics") //
                                            : i18nc("@action:button The Audit Log is a detailed error log from the gnupg backend", "Show Audit Log"));
    dialog->setWindowTitle(title);
    QDialogButtonBox *box = new QDialogButtonBox(QDialogButtonBox::Yes | QDialogButtonBox::No, dialog);
    KGuiItem::assign(box->button(QDialogButtonBox::Yes), KGuiItem{auditLogButtonText});
    KGuiItem::assign(box->button(QDialogButtonBox::No), KStandardGuiItem::ok());

    if (options & KMessageBox::WindowModal) {
        dialog->setWindowModality(Qt::WindowModal);
    }
    dialog->setModal(true);

    // Flag as Dangerous to make the Ok button the default button
    const auto choice = KMessageBox::createKMessageBox(dialog, box, icon, text, QStringList{}, QString{}, nullptr, options | KMessageBox::Dangerous);
    if (choice == QDialogButtonBox::Yes) {
        // FIXME: handle WId case???
        AuditLogViewer::showAuditLog(dialog->parentWidget(), auditLog);
    }
}

void MessageBox::information(QWidget *parent, const QString &text, const Kleo::AuditLogEntry &auditLog, const QString &title, KMessageBox::Options options)
{
    if (showAuditLogButton(auditLog)) {
        showMessageBoxWithAuditLogButton(new QDialog{parent},
                                         QMessageBox::Information,
                                         text,
                                         auditLog,
                                         title.isEmpty() ? i18nc("@title:window", "Information") : title,
                                         options);
    } else {
        KMessageBox::information(parent, text, title, {}, options);
    }
}

void MessageBox::informationWId(WId parentId, const QString &text, const Kleo::AuditLogEntry &auditLog, const QString &title, KMessageBox::Options options)
{
    if (showAuditLogButton(auditLog)) {
        showMessageBoxWithAuditLogButton(createWIdDialog(parentId),
                                         QMessageBox::Information,
                                         text,
                                         auditLog,
                                         title.isEmpty() ? i18nc("@title:window", "Information") : title,
                                         options);
    } else {
        KMessageBox::informationWId(parentId, text, title, {}, options);
    }
}

void MessageBox::error(QWidget *parent, const QString &text, const Kleo::AuditLogEntry &auditLog, const QString &title, KMessageBox::Options options)
{
    if (showAuditLogButton(auditLog)) {
        showMessageBoxWithAuditLogButton(new QDialog{parent},
                                         QMessageBox::Critical,
                                         text,
                                         auditLog,
                                         title.isEmpty() ? i18nc("@title:window", "Error") : title,
                                         options);
    } else {
        KMessageBox::error(parent, text, title, options);
    }
}

void MessageBox::errorWId(WId parentId, const QString &text, const Kleo::AuditLogEntry &auditLog, const QString &title, KMessageBox::Options options)
{
    if (showAuditLogButton(auditLog)) {
        showMessageBoxWithAuditLogButton(createWIdDialog(parentId),
                                         QMessageBox::Critical,
                                         text,
                                         auditLog,
                                         title.isEmpty() ? i18nc("@title:window", "Error") : title,
                                         options);
    } else {
        KMessageBox::errorWId(parentId, text, title, options);
    }
}
