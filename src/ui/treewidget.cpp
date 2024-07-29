/*
    ui/treewidget.cpp

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "treewidget.h"

#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>

#include <QContextMenuEvent>
#include <QHeaderView>
#include <QMenu>

using namespace Kleo;

class TreeWidget::Private
{
    TreeWidget *q;

public:
    QMenu *mHeaderPopup = nullptr;
    QList<QAction *> mColumnActions;
    QString mStateGroupName;
    std::vector<bool> mColumnForcedHidden;

    Private(TreeWidget *qq)
        : q(qq)
    {
    }

    ~Private()
    {
        saveColumnLayout();
    }
    void saveColumnLayout();
};

TreeWidget::TreeWidget(QWidget *parent)
    : QTreeWidget::QTreeWidget(parent)
    , d{new Private(this)}
{
    header()->installEventFilter(this);
}

TreeWidget::~TreeWidget() = default;

void TreeWidget::forceColumnHidden(int column)
{
    if (column > columnCount()) {
        return;
    }
    // ensure that the mColumnForcedHidden vector is initialized
    d->mColumnForcedHidden.resize(columnCount(), false);
    d->mColumnForcedHidden[column] = true;
}

void TreeWidget::Private::saveColumnLayout()
{
    if (mStateGroupName.isEmpty()) {
        return;
    }
    auto config = KConfigGroup(KSharedConfig::openStateConfig(), mStateGroupName);
    auto header = q->header();

    QVariantList columnVisibility;
    QVariantList columnOrder;
    QVariantList columnWidths;
    const int headerCount = header->count();
    columnVisibility.reserve(headerCount);
    columnWidths.reserve(headerCount);
    columnOrder.reserve(headerCount);
    for (int i = 0; i < headerCount; ++i) {
        columnVisibility << QVariant(!q->isColumnHidden(i));
        columnWidths << QVariant(header->sectionSize(i));
        columnOrder << QVariant(header->visualIndex(i));
    }

    config.writeEntry("ColumnVisibility", columnVisibility);
    config.writeEntry("ColumnOrder", columnOrder);
    config.writeEntry("ColumnWidths", columnWidths);

    config.writeEntry("SortAscending", (int)header->sortIndicatorOrder());
    if (header->isSortIndicatorShown()) {
        config.writeEntry("SortColumn", header->sortIndicatorSection());
    } else {
        config.writeEntry("SortColumn", -1);
    }
    config.sync();
}

bool TreeWidget::restoreColumnLayout(const QString &stateGroupName)
{
    if (stateGroupName.isEmpty()) {
        return false;
    }
    // ensure that the mColumnForcedHidden vector is initialized
    d->mColumnForcedHidden.resize(columnCount(), false);

    d->mStateGroupName = stateGroupName;
    auto config = KConfigGroup(KSharedConfig::openStateConfig(), d->mStateGroupName);
    auto header = this->header();

    QVariantList columnVisibility = config.readEntry("ColumnVisibility", QVariantList());
    QVariantList columnOrder = config.readEntry("ColumnOrder", QVariantList());
    QVariantList columnWidths = config.readEntry("ColumnWidths", QVariantList());

    if (!columnVisibility.isEmpty() && !columnOrder.isEmpty() && !columnWidths.isEmpty()) {
        for (int i = 0; i < header->count(); ++i) {
            if (d->mColumnForcedHidden[i] || i >= columnOrder.size() || i >= columnWidths.size() || i >= columnVisibility.size()) {
                // Hide columns that are forced hidden and new columns that were not around the last time we saved
                hideColumn(i);
                continue;
            }
            bool visible = columnVisibility[i].toBool();
            int width = columnWidths[i].toInt();
            int order = columnOrder[i].toInt();

            header->resizeSection(i, width ? width : header->defaultSectionSize());
            header->moveSection(header->visualIndex(i), order);

            if (!visible) {
                hideColumn(i);
            }
        }
    } else {
        for (int i = 0; i < header->count(); ++i) {
            if (d->mColumnForcedHidden[i]) {
                hideColumn(i);
            }
        }
    }

    int sortOrder = config.readEntry("SortAscending", (int)Qt::AscendingOrder);
    int sortColumn = config.readEntry("SortColumn", 0);
    if (sortColumn >= 0) {
        sortByColumn(sortColumn, (Qt::SortOrder)sortOrder);
    }
    connect(header, &QHeaderView::sectionResized, this, [this]() {
        d->saveColumnLayout();
    });
    connect(header, &QHeaderView::sectionMoved, this, [this]() {
        d->saveColumnLayout();
    });
    connect(header, &QHeaderView::sortIndicatorChanged, this, [this]() {
        d->saveColumnLayout();
    });
    return !columnVisibility.isEmpty() && !columnOrder.isEmpty() && !columnWidths.isEmpty();
}

bool TreeWidget::eventFilter(QObject *watched, QEvent *event)
{
    if ((watched == header()) && (event->type() == QEvent::ContextMenu)) {
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
                    if (columnWidth(col) == 0 || columnWidth(col) == header()->defaultSectionSize()) {
                        resizeColumnToContents(col);
                    }
                } else {
                    hideColumn(col);
                }

                if (action->isChecked()) {
                    Q_EMIT columnEnabled(col);
                } else {
                    Q_EMIT columnDisabled(col);
                }
                d->saveColumnLayout();
            });
        }

        for (QAction *action : std::as_const(d->mColumnActions)) {
            const int column = action->data().toInt();
            action->setChecked(!isColumnHidden(column));
        }

        auto numVisibleColumns = std::count_if(d->mColumnActions.cbegin(), d->mColumnActions.cend(), [](const auto &action) {
            return action->isChecked();
        });

        for (auto action : std::as_const(d->mColumnActions)) {
            action->setEnabled(numVisibleColumns != 1 || !action->isChecked());
        }

        d->mHeaderPopup->popup(mapToGlobal(e->pos()));
        return true;
    }

    return QTreeWidget::eventFilter(watched, event);
}

void TreeWidget::focusInEvent(QFocusEvent *event)
{
    QTreeWidget::focusInEvent(event);
    // workaround for wrong order of accessible focus events emitted by Qt for QTreeWidget;
    // on first focusing of QTreeWidget, Qt sends focus event for current item before focus event for tree
    // so that orca doesn't announce the current item;
    // on re-focusing of QTreeWidget, Qt only sends focus event for tree
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
