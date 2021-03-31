/*
    progressdialog.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"
#include <QProgressDialog>

#ifndef QT_NO_PROGRESSDIALOG

#include <QString>

#include <qgpgme/job.h>
namespace Kleo
{

/**
   @short A progress dialog for Kleo::Jobs
*/
class KLEO_EXPORT ProgressDialog : public QProgressDialog
{
    Q_OBJECT
public:
    ProgressDialog(QGpgME::Job *job, const QString &baseText,
                   QWidget *widget = nullptr, Qt::WindowFlags f = {});
    ~ProgressDialog();

public Q_SLOTS:
    /*! reimplementation */
    void setMinimumDuration(int ms);

private Q_SLOTS:
    void slotProgress(const QString &what, int current, int total);
    void slotDone();
private:
    QString mBaseText;
};

}

#else
# ifndef LIBKLEO_NO_PROGRESSDIALOG
#  define LIBKLEO_NO_PROGRESSDIALOG
# endif
#endif // QT_NO_PROGRESSDIALOG

