/*
    ui/navigatabletreewidget.cpp

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
    // make column by column keyboard navigation with Left/Right possible by switching
    // the selection behavior to SelectItems before calling the parent class's moveCursor,
    // because it ignores MoveLeft/MoveRight if the selection behavior is SelectRows;
    // moreover, temporarily disable exanding of items to prevent expanding/collapsing
    // on MoveLeft/MoveRight
    if ((cursorAction != MoveLeft) && (cursorAction != MoveRight)) {
        return QTreeWidget::moveCursor(cursorAction, modifiers);
    }

    const auto savedSelectionBehavior = selectionBehavior();
    setSelectionBehavior(SelectItems);
    const auto savedItemsExpandable = itemsExpandable();
    setItemsExpandable(false);

    const auto result = QTreeWidget::moveCursor(cursorAction, modifiers);

    setItemsExpandable(savedItemsExpandable);
    setSelectionBehavior(savedSelectionBehavior);

    return result;
}

#include "moc_navigatabletreewidget.cpp"
