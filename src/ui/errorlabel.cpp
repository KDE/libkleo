/*
    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "errorlabel.h"

#include <KColorScheme>

#include <QCoreApplication>

using namespace Kleo;

static void updatePalette(ErrorLabel *label)
{
    QPalette palette;
    for (int i = 0; i < QPalette::NColorGroups; ++i) {
        const auto cg = static_cast<QPalette::ColorGroup>(i);
        const auto colors = KColorScheme(cg, KColorScheme::View);
        palette.setBrush(cg, QPalette::Window, colors.background(KColorScheme::NegativeBackground));
        palette.setBrush(cg, QPalette::WindowText, colors.foreground(KColorScheme::NegativeText));
    }
    label->setPalette(palette);
}

ErrorLabel::ErrorLabel(QWidget *parent)
    : QLabel{parent}
{
    updatePalette(this);
    qApp->installEventFilter(this);
}

ErrorLabel::~ErrorLabel()
{
    qApp->removeEventFilter(this);
}

bool ErrorLabel::eventFilter(QObject *obj, QEvent *event)
{
    if (obj == qApp && event->type() == QEvent::ApplicationPaletteChange) {
        updatePalette(this);
    }
    return false;
}

#include "moc_errorlabel.cpp"
