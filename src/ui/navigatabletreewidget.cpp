/*
    ui/navigatabletreewidget.h

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "navigatabletreewidget.h"

using namespace Kleo;

QModelIndex NavigatableTreeWidget::moveCursor(QAbstractItemView::CursorAction cursorAction, Qt::KeyboardModifiers modifiers)
{
    // make keyboard navigation with Left/Right possible by switching the selection behavior to SelectItems
    // before calling QTreeWidget::moveCursor, because QTreeWidget::moveCursor ignores MoveLeft/MoveRight
    // if the selection behavior is SelectRows
    if ((cursorAction == MoveLeft) || (cursorAction == MoveRight)) {
        setSelectionBehavior(SelectItems);
    }
    const auto result = QTreeWidget::moveCursor(cursorAction, modifiers);
    if ((cursorAction == MoveLeft) || (cursorAction == MoveRight)) {
        setSelectionBehavior(SelectRows);
    }
    return result;
}

