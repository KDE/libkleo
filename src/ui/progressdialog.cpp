/*
    progressdialog.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "progressdialog.h"

#ifndef QT_NO_PROGRESSDIALOG

#include "progressbar.h"

#include <kleo_ui_debug.h>

#include <KLocalizedString>

#include <QTimer>

Kleo::ProgressDialog::ProgressDialog(QGpgME::Job *job, const QString &baseText, QWidget *creator, Qt::WindowFlags f)
    : QProgressDialog(creator, f)
    , mBaseText(baseText)
{
    Q_ASSERT(job);
    setBar(new ProgressBar(this /*, "replacement progressbar in Kleo::ProgressDialog"*/));

    setMinimumDuration(2000 /*ms*/);
    setAutoReset(false);
    setAutoClose(false);
    setLabelText(baseText);
    setModal(false);
    setRange(0, 0); // activate busy indicator

    connect(job, &QGpgME::Job::jobProgress, this, &ProgressDialog::slotProgress);
    connect(job, &QGpgME::Job::done, this, &ProgressDialog::slotDone);
    connect(this, &QProgressDialog::canceled, job, &QGpgME::Job::slotCancel);

    QTimer::singleShot(minimumDuration(), this, &ProgressDialog::forceShow);
}

Kleo::ProgressDialog::~ProgressDialog()
{
}

void Kleo::ProgressDialog::setMinimumDuration(int ms)
{
    if (0 < ms && ms < minimumDuration()) {
        QTimer::singleShot(ms, this, &ProgressDialog::forceShow);
    }
    QProgressDialog::setMinimumDuration(ms);
}

void Kleo::ProgressDialog::slotProgress(int current, int total)
{
    qCDebug(KLEO_UI_LOG) << "Kleo::ProgressDialog::slotProgress(" << current << "," << total << ")";
    setRange(current, total);
}

void Kleo::ProgressDialog::slotDone()
{
    qCDebug(KLEO_UI_LOG) << "Kleo::ProgressDialog::slotDone()";
    hide();
    deleteLater();
}

#endif // QT_NO_PROGRESSDIALOG

#include "moc_progressdialog.cpp"
