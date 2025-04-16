/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2025 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include "applicationpalettewatcher.h"

#include <QCoreApplication>

ApplicationPaletteWatcher::ApplicationPaletteWatcher(QObject *parent)
    : QObject{parent}
{
    qApp->installEventFilter(this);
}

ApplicationPaletteWatcher::~ApplicationPaletteWatcher()
{
    qApp->removeEventFilter(this);
}

bool ApplicationPaletteWatcher::eventFilter(QObject *obj, QEvent *event)
{
    if (obj == qApp && event->type() == QEvent::ApplicationPaletteChange) {
        Q_EMIT paletteChanged();
    }
    return false;
}

#include "moc_applicationpalettewatcher.cpp"
