/*
    progressbar.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "progressbar.h"

#include <QTimer>
#include "kleo_ui_debug.h"

static const int busyTimerTickInterval = 100;
static const int busyTimerTickIncrement = 5;

Kleo::ProgressBar::ProgressBar(QWidget *parent)
    : QProgressBar(parent),
      mRealProgress(-1)
{
    mBusyTimer = new QTimer(this);
    connect(mBusyTimer, &QTimer::timeout, this, &ProgressBar::slotBusyTimerTick);
    fixup(true);
}

void Kleo::ProgressBar::slotProgress(const QString &, int cur, int tot)
{
    setRange(cur, tot);
}

void Kleo::ProgressBar::slotProgress(const QString &, int, int cur, int tot)
{
    setRange(cur, tot);
}

void Kleo::ProgressBar::setMaximum(int total)
{
    qCDebug(KLEO_UI_LOG) << "Kleo::ProgressBar::setMaximum(" << total << " )";
    if (total == maximum()) {
        return;
    }
    QProgressBar::setMaximum(0);
    fixup(false);
}

void Kleo::ProgressBar::setValue(int p)
{
    qCDebug(KLEO_UI_LOG) << "Kleo::ProgressBar::setValue(" << p << " )";
    mRealProgress = p;
    fixup(true);
}

void Kleo::ProgressBar::reset()
{
    mRealProgress = -1;
    fixup(true);
}

void Kleo::ProgressBar::slotBusyTimerTick()
{
    fixup(false);
    if (mBusyTimer->isActive()) {
        QProgressBar::setValue(QProgressBar::value() + busyTimerTickIncrement);
    }
}

void Kleo::ProgressBar::fixup(bool newValue)
{
    const int cur = QProgressBar::value();
    const int tot = QProgressBar::maximum();

    qCDebug(KLEO_UI_LOG) << "Kleo::ProgressBar::startStopBusyTimer() cur =" << cur << "; tot =" << tot << "; real =" << mRealProgress;

    if ((newValue && mRealProgress < 0) || (!newValue && cur < 0)) {
        qCDebug(KLEO_UI_LOG) << "(new value) switch to reset";
        mBusyTimer->stop();
        if (newValue) {
            QProgressBar::reset();
        }
        mRealProgress = -1;
    } else if (tot == 0) {
        qCDebug(KLEO_UI_LOG) << "(new value) switch or stay in busy";
        if (!mBusyTimer->isActive()) {
            mBusyTimer->start(busyTimerTickInterval);
            if (newValue) {
                QProgressBar::setValue(mRealProgress);
            }
        }
    } else {
        qCDebug(KLEO_UI_LOG) << "(new value) normal progress";
        mBusyTimer->stop();
        if (QProgressBar::value() != mRealProgress) {
            QProgressBar::setValue(mRealProgress);
        }
    }
}

