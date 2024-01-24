/*
    ui/treewidget.cpp

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "treewidget.h"

#include <KLocalizedString>

#include <QContextMenuEvent>
#include <QHeaderView>
#include <QMenu>

using namespace Kleo;

class TreeWidget::Private
{
public:
    QMenu *mHeaderPopup = nullptr;
    QList<QAction *> mColumnActions;
};

TreeWidget::TreeWidget(QWidget *parent)
    : QTreeWidget::QTreeWidget(parent)
    , d{new Private}
{
    header()->installEventFilter(this);
}

TreeWidget::~TreeWidget() = default;

bool TreeWidget::eventFilter(QObject *watched, QEvent *event)
{
    Q_UNUSED(watched)
    if (event->type() == QEvent::ContextMenu) {
        auto e = static_cast<QContextMenuEvent *>(event);

        if (!d->mHeaderPopup) {
            d->mHeaderPopup = new QMenu(this);
            d->mHeaderPopup->setTitle(i18nc("@title:menu", "View Columns"));
            for (int i = 0; i < model()->columnCount(); ++i) {
                QAction *tmp = d->mHeaderPopup->addAction(model()->headerData(i, Qt::Horizontal).toString());
                tmp->setData(QVariant(i));
                tmp->setCheckable(true);
                d->mColumnActions << tmp;
            }

            connect(d->mHeaderPopup, &QMenu::triggered, this, [this](QAction *action) {
                const int col = action->data().toInt();
                if (action->isChecked()) {
                    showColumn(col);
                } else {
                    hideColumn(col);
                }

                if (action->isChecked()) {
                    Q_EMIT columnEnabled(col);
                } else {
                    Q_EMIT columnDisabled(col);
                }
            });
        }

        for (QAction *action : std::as_const(d->mColumnActions)) {
            const int column = action->data().toInt();
            action->setChecked(!isColumnHidden(column));
        }

        d->mHeaderPopup->popup(mapToGlobal(e->pos()));
        return true;
    }

    return false;
}

QModelIndex TreeWidget::moveCursor(QAbstractItemView::CursorAction cursorAction, Qt::KeyboardModifiers modifiers)
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

#include "moc_treewidget.cpp"
