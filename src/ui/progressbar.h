/*
    progressbar.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"
#include <QProgressBar>
class QTimer;

namespace Kleo
{

/**
   @short A QProgressBar with self-powered busy indicator
*/
class KLEO_EXPORT ProgressBar : public QProgressBar
{
    Q_OBJECT
public:
    explicit ProgressBar(QWidget *parent = nullptr);

public Q_SLOTS:
    void slotProgress(const QString &message, int type, int current, int total);
    void slotProgress(const QString &message, int current, int total);
    /*! reimplementation to support self-powered busy indicator */
    void setValue(int progress);
    /*! reimplementation to support self-powered busy indicator */
    void setMaximum(int total);
    /*! reimplementation to support self-powered busy indicator */
    void reset();
    /*! reimplementation to preserve visibility */
    void setRange(int cur, int tot)
    {
        QProgressBar::setRange(cur, tot);
    }

private Q_SLOTS:
    void slotBusyTimerTick();

private:
    void fixup(bool);

private:
    QTimer *mBusyTimer = nullptr;
    int mRealProgress;
};
}

