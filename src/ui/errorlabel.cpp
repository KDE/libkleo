/*
    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "errorlabel.h"

#include <KColorScheme>

using namespace Kleo;

ErrorLabel::ErrorLabel(QWidget *parent)
    : QLabel{parent}
{
    const auto colors = KColorScheme(QPalette::Active, KColorScheme::View);
    QPalette palette;
    palette.setBrush(QPalette::Window, colors.background(KColorScheme::NegativeBackground));
    palette.setBrush(QPalette::WindowText, colors.foreground(KColorScheme::NegativeText));
    setPalette(palette);
}

ErrorLabel::~ErrorLabel() = default;

#include "moc_errorlabel.cpp"
