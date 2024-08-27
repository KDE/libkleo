/*
    ui/treeview.cpp

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "treeview.h"

#include <models/keylist.h>

#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>

#include <QClipboard>
#include <QContextMenuEvent>
#include <QGuiApplication>
#include <QHeaderView>
#include <QMenu>

using namespace Kleo;

static const int MAX_AUTOMATIC_COLUMN_WIDTH = 400;

class TreeView::Private
{
    TreeView *q;

public:
    QMenu *mHeaderPopup = nullptr;
    QList<QAction *> mColumnActions;
    QString mStateGroupName;

    Private(TreeView *qq)
        : q(qq)
    {
    }

    ~Private()
    {
        saveColumnLayout();
    }
    void saveColumnLayout();
};

TreeView::TreeView(QWidget *parent)
    : QTreeView::QTreeView(parent)
    , d{new Private(this)}
{
    header()->installEventFilter(this);
}

TreeView::~TreeView() = default;

bool TreeView::eventFilter(QObject *watched, QEvent *event)
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
                    if (columnWidth(col) == 0 || columnWidth(col) == header()->defaultSectionSize()) {
                        resizeColumnToContents(col);
                        setColumnWidth(col, std::min(columnWidth(col), MAX_AUTOMATIC_COLUMN_WIDTH));
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

    return false;
}

void TreeView::Private::saveColumnLayout()
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

bool TreeView::restoreColumnLayout(const QString &stateGroupName)
{
    if (stateGroupName.isEmpty()) {
        return false;
    }
    d->mStateGroupName = stateGroupName;
    auto config = KConfigGroup(KSharedConfig::openStateConfig(), d->mStateGroupName);
    auto header = this->header();

    QVariantList columnVisibility = config.readEntry("ColumnVisibility", QVariantList());
    QVariantList columnOrder = config.readEntry("ColumnOrder", QVariantList());
    QVariantList columnWidths = config.readEntry("ColumnWidths", QVariantList());

    if (!columnVisibility.isEmpty() && !columnOrder.isEmpty() && !columnWidths.isEmpty()) {
        for (int i = 0; i < header->count(); ++i) {
            if (i >= columnOrder.size() || i >= columnWidths.size() || i >= columnVisibility.size()) {
                // An additional column that was not around last time we saved.
                // We default to hidden.
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
    }

    int sortOrder = config.readEntry("SortAscending", (int)Qt::AscendingOrder);
    int sortColumn = config.readEntry("SortColumn", isSortingEnabled() ? 0 : -1);
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
    if (event == QKeySequence::Copy) {
        const QModelIndex index = currentIndex();
        if (index.isValid() && model()) {
            QVariant variant = model()->data(index, Kleo::ClipboardRole);
            if (!variant.isValid()) {
                variant = model()->data(index, Qt::DisplayRole);
            }
            if (variant.canConvert<QString>()) {
                QGuiApplication::clipboard()->setText(variant.toString());
            }
        }
        event->accept();
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
    d->mStateGroupName = stateGroupName;
    d->saveColumnLayout();
}

void TreeView::resizeToContentsLimited()
{
    for (int i = 0; i < model()->columnCount(); i++) {
        resizeColumnToContents(i);
        setColumnWidth(i, std::min(columnWidth(i), MAX_AUTOMATIC_COLUMN_WIDTH));
    }
}

#include "moc_treeview.cpp"
