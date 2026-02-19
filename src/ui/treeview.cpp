/*
    ui/treeview.cpp

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "treeview.h"

#include "treeview_p.h"

#include <QHeaderView>
#include <QKeyEvent>

using namespace Kleo;

TreeView::TreeView(QWidget *parent)
    : QTreeView::QTreeView(parent)
    , d{new TreeViewPrivate(this)}
{
    header()->installEventFilter(this);
}

TreeView::~TreeView() = default;

bool TreeView::eventFilter(QObject *watched, QEvent *event)
{
    return d->eventFilter(watched, event);
}

bool TreeView::restoreColumnLayout(const QString &stateGroupName)
{
    return d->restoreColumnLayout(stateGroupName);
}

void TreeView::focusInEvent(QFocusEvent *event)
{
    QTreeView::focusInEvent(event);
    // workaround for wrong order of accessible focus events emitted by Qt for QTreeView;
    // on first focusing of QTreeView, Qt sends focus event for current item before focus event for tree
    // so that orca doesn't announce the current item;
    // on re-focusing of QTreeView, Qt only sends focus event for tree
    auto forceAccessibleFocusEventForCurrentItem = [this]() {
        // force Qt to send a focus event for the current item to accessibility
        // tools; otherwise, the user has no idea which item is selected when the
        // list gets keyboard input focus
        const QModelIndex index = currentIndex();
        if (index.isValid()) {
            currentChanged(index, QModelIndex{});
        }
    };
    // queue the invocation, so that it happens after the widget itself got focus
    QMetaObject::invokeMethod(this, forceAccessibleFocusEventForCurrentItem, Qt::QueuedConnection);
}

void TreeView::keyPressEvent(QKeyEvent *event)
{
    d->keyPressEvent(event);
    if (event->isAccepted()) {
        return;
    }

    QTreeView::keyPressEvent(event);
}

QModelIndex TreeView::moveCursor(QAbstractItemView::CursorAction cursorAction, Qt::KeyboardModifiers modifiers)
{
    // make column by column keyboard navigation with Left/Right possible by switching
    // the selection behavior to SelectItems before calling the parent class's moveCursor,
    // because it ignores MoveLeft/MoveRight if the selection behavior is SelectRows;
    // moreover, temporarily disable exanding of items to prevent expanding/collapsing
    // on MoveLeft/MoveRight
    if ((cursorAction != MoveLeft) && (cursorAction != MoveRight)) {
        return QTreeView::moveCursor(cursorAction, modifiers);
    }

    const auto savedSelectionBehavior = selectionBehavior();
    setSelectionBehavior(SelectItems);
    const auto savedItemsExpandable = itemsExpandable();
    setItemsExpandable(false);

    const auto result = QTreeView::moveCursor(cursorAction, modifiers);

    setItemsExpandable(savedItemsExpandable);
    setSelectionBehavior(savedSelectionBehavior);

    return result;
}

void TreeView::saveColumnLayout(const QString &stateGroupName)
{
    d->saveColumnLayout(stateGroupName);
}

void TreeView::resizeToContentsLimited()
{
    d->resizeToContentsLimited();
}

QMenu *TreeView::columnVisibilityMenu()
{
    return d->columnVisibilityMenu();
}

QMenu *TreeView::columnSortingMenu()
{
    return d->columnSortingMenu();
}

#include "moc_treeview.cpp"
