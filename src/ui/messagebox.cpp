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

// static
void MessageBox::auditLog(QWidget *parent, const Job *job, const QString &caption)
{
    if (!job) {
        return;
    }
    AuditLogViewer::showAuditLog(parent, AuditLogEntry::fromJob(job), caption);
}

// static
void MessageBox::auditLog(QWidget *parent, const QString &log, const QString &caption)
{
    AuditLogViewer::showAuditLog(parent, AuditLogEntry{log, Error{}}, caption);
}

// static
void MessageBox::auditLog(QWidget *parent, const Job *job)
{
    if (!job) {
        return;
    }
    AuditLogViewer::showAuditLog(parent, AuditLogEntry::fromJob(job));
}

// static
void MessageBox::auditLog(QWidget *parent, const QString &log)
{
    AuditLogViewer::showAuditLog(parent, AuditLogEntry{log, Error{}});
}

static QString to_information_string(const SigningResult &result)
{
    return (result.error() //
                ? i18n("Signing failed: %1", QString::fromLocal8Bit(result.error().asString()))
                : i18n("Signing successful"));
}

static QString to_error_string(const SigningResult &result)
{
    return to_information_string(result);
}

static QString to_information_string(const EncryptionResult &result)
{
    return (result.error() //
                ? i18n("Encryption failed: %1", QString::fromLocal8Bit(result.error().asString()))
                : i18n("Encryption successful"));
}

static QString to_error_string(const EncryptionResult &result)
{
    return to_information_string(result);
}

static QString to_information_string(const SigningResult &sresult, const EncryptionResult &eresult)
{
    return to_information_string(sresult) + QLatin1Char('\n') + to_information_string(eresult);
}

static QString to_error_string(const SigningResult &sresult, const EncryptionResult &eresult)
{
    return to_information_string(sresult, eresult);
}

// static
void MessageBox::information(QWidget *parent, const SigningResult &result, const Job *job, KMessageBox::Options options)
{
    information(parent, result, job, i18n("Signing Result"), options);
}

// static
void MessageBox::information(QWidget *parent, const SigningResult &result, const Job *job, const QString &caption, KMessageBox::Options options)
{
    make(parent, QMessageBox::Information, to_information_string(result), job, caption, options);
}

// static
void MessageBox::error(QWidget *parent, const SigningResult &result, const Job *job, KMessageBox::Options options)
{
    error(parent, result, job, i18n("Signing Error"), options);
}

// static
void MessageBox::error(QWidget *parent, const SigningResult &result, const Job *job, const QString &caption, KMessageBox::Options options)
{
    make(parent, QMessageBox::Critical, to_error_string(result), job, caption, options);
}

// static
void MessageBox::information(QWidget *parent, const EncryptionResult &result, const Job *job, KMessageBox::Options options)
{
    information(parent, result, job, i18n("Encryption Result"), options);
}

// static
void MessageBox::information(QWidget *parent, const EncryptionResult &result, const Job *job, const QString &caption, KMessageBox::Options options)
{
    make(parent, QMessageBox::Information, to_information_string(result), job, caption, options);
}

// static
void MessageBox::error(QWidget *parent, const EncryptionResult &result, const Job *job, KMessageBox::Options options)
{
    error(parent, result, job, i18n("Encryption Error"), options);
}

// static
void MessageBox::error(QWidget *parent, const EncryptionResult &result, const Job *job, const QString &caption, KMessageBox::Options options)
{
    make(parent, QMessageBox::Critical, to_error_string(result), job, caption, options);
}

// static
void MessageBox::information(QWidget *parent, const SigningResult &sresult, const EncryptionResult &eresult, const Job *job, KMessageBox::Options options)
{
    information(parent, sresult, eresult, job, i18n("Encryption Result"), options);
}

// static
void MessageBox::information(QWidget *parent,
                             const SigningResult &sresult,
                             const EncryptionResult &eresult,
                             const Job *job,
                             const QString &caption,
                             KMessageBox::Options options)
{
    make(parent, QMessageBox::Information, to_information_string(sresult, eresult), job, caption, options);
}

// static
void MessageBox::error(QWidget *parent, const SigningResult &sresult, const EncryptionResult &eresult, const Job *job, KMessageBox::Options options)
{
    error(parent, sresult, eresult, job, i18n("Encryption Error"), options);
}

// static
void MessageBox::error(QWidget *parent,
                       const SigningResult &sresult,
                       const EncryptionResult &eresult,
                       const Job *job,
                       const QString &caption,
                       KMessageBox::Options options)
{
    make(parent, QMessageBox::Critical, to_error_string(sresult, eresult), job, caption, options);
}

// static
bool MessageBox::showAuditLogButton(const QGpgME::Job *job)
{
    if (!job) {
        qCDebug(KLEO_UI_LOG) << "not showing audit log button (no job instance)";
        return false;
    }
    if (!GpgME::hasFeature(GpgME::AuditLogFeature, 0)) {
        qCDebug(KLEO_UI_LOG) << "not showing audit log button (gpgme too old)";
        return false;
    }
    if (!job->isAuditLogSupported()) {
        qCDebug(KLEO_UI_LOG) << "not showing audit log button (not supported)";
        return false;
    }
    if (job->auditLogError().code() == GPG_ERR_NO_DATA) {
        qCDebug(KLEO_UI_LOG) << "not showing audit log button (GPG_ERR_NO_DATA)";
        return false;
    }
    if (!job->auditLogError() && job->auditLogAsHtml().isEmpty()) {
        qCDebug(KLEO_UI_LOG) << "not showing audit log button (success, but result empty)";
        return false;
    }
    return true;
}

// static
void MessageBox::make(QWidget *parent, QMessageBox::Icon icon, const QString &text, const Job *job, const QString &caption, KMessageBox::Options options)
{
    QDialog *dialog = new QDialog(parent);
    dialog->setWindowTitle(caption);
    QDialogButtonBox *box = new QDialogButtonBox(showAuditLogButton(job) ? (QDialogButtonBox::Yes | QDialogButtonBox::No) : QDialogButtonBox::Yes, parent);
    QPushButton *yesButton = box->button(QDialogButtonBox::Yes);
    yesButton->setDefault(true);
    // dialog->setEscapeButton(KDialog::Yes);
    dialog->setObjectName(QStringLiteral("error"));
    dialog->setModal(true);
    KGuiItem::assign(yesButton, KStandardGuiItem::ok());
    if (GpgME::hasFeature(GpgME::AuditLogFeature, 0)) {
        KGuiItem::assign(box->button(QDialogButtonBox::No), KGuiItem(i18n("&Show Audit Log")));
    }

    if (QDialogButtonBox::No == KMessageBox::createKMessageBox(dialog, box, icon, text, QStringList(), QString(), nullptr, options)) {
        auditLog(nullptr, job);
    }
}
