/*
    gnupgviewer.h

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QProcess>
#include <QString>
#include <QStringList>
#include <QTextEdit>

namespace Kleo
{
class GnuPGProcessBase;
}

class GnuPGViewer : public QTextEdit
{
    Q_OBJECT
public:
    GnuPGViewer(QWidget *parent = nullptr);
    ~GnuPGViewer();

    void setProcess(Kleo::GnuPGProcessBase *process);

private Q_SLOTS:
    void slotStdout();
    void slotStderr();
    void slotStatus(Kleo::GnuPGProcessBase *, const QString &, const QStringList &);
    void slotProcessExited(int, QProcess::ExitStatus);

private:
    Kleo::GnuPGProcessBase *mProcess = nullptr;
    QString mLastStdout, mLastStderr, mLastStatus;
};
