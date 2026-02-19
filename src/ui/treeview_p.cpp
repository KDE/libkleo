/*
    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2026 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "treeview_p.h"

#include <models/keylist.h>
#include <utils/algorithm.h>

#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>

#include <QClipboard>
#include <QContextMenuEvent>
#include <QGuiApplication>
#include <QHeaderView>
#include <QKeyEvent>
#include <QMenu>

using namespace Kleo;

TreeViewPrivate::TreeViewPrivate(QTreeView *qq)
    : q{qq}
    , mSortColumnActionGroup{nullptr}
    , mSortDirectionActionGroup{nullptr}
{
}

TreeViewPrivate::~TreeViewPrivate()
{
    saveColumnLayout();
}

QMenu *TreeViewPrivate::columnVisibilityMenu()
{
    if (!mColumnVisibilityMenu) {
        mColumnVisibilityMenu = new QMenu(q);
        mColumnVisibilityMenu->setTitle(i18nc("@title:menu", "View Columns"));
        for (int i = 0; i < q->model()->columnCount(); ++i) {
            auto action = mColumnVisibilityMenu->addAction(q->model()->headerData(i, Qt::Horizontal).toString());
            action->setData(i);
            action->setCheckable(true);
            QObject::connect(action, &QAction::triggered, q, [action, this]() {
                columnVisibilityActionTriggered(action);
            });
        }
    }

    updateColumnVisibilityActions();

    return mColumnVisibilityMenu;
}

void TreeViewPrivate::updateColumnVisibilityActions()
{
    const auto actions = mColumnVisibilityMenu->actions();
    for (QAction *action : std::as_const(actions)) {
        const int column = action->data().toInt();
        action->setChecked(!q->isColumnHidden(column));
    }
    const auto numVisibleColumns = Kleo::count_if(actions, std::mem_fn(&QAction::isChecked));
    for (auto action : std::as_const(actions)) {
        action->setEnabled(numVisibleColumns != 1 || !action->isChecked());
    }
}

QMenu *TreeViewPrivate::columnSortingMenu()
{
    if (!mColumnSortingMenu) {
        mColumnSortingMenu = new QMenu(q);
        mColumnSortingMenu->addSection(i18nc("@title:menu title for a list of table columns to choose for sorting", "Sort by"));
        for (int i = 0; i < q->model()->columnCount(); ++i) {
            auto action = mColumnSortingMenu->addAction(q->model()->headerData(i, Qt::Horizontal).toString());
            action->setData(i);
            action->setCheckable(true);
            mSortColumnActionGroup.addAction(action);
            QObject::connect(action, &QAction::triggered, q, [action, this](bool checked) {
                if (checked) {
                    const int column = action->data().toInt();
                    q->header()->setSortIndicator(column, q->header()->sortIndicatorOrder());
                }
            });
        }

        mColumnSortingMenu->addSection(i18nc("@title:menu", "Sort Direction"));
        auto ascendingAction = mColumnSortingMenu->addAction(i18nc("@action:inmenu", "Ascending"));
        ascendingAction->setCheckable(true);
        mSortDirectionActionGroup.addAction(ascendingAction);
        QObject::connect(ascendingAction, &QAction::triggered, q, [this](bool checked) {
            if (checked) {
                q->header()->setSortIndicator(q->header()->sortIndicatorSection(), Qt::AscendingOrder);
            }
        });
        auto descendingAction = mColumnSortingMenu->addAction(i18nc("@action:inmenu", "Descending"));
        descendingAction->setCheckable(true);
        mSortDirectionActionGroup.addAction(descendingAction);
        QObject::connect(descendingAction, &QAction::triggered, q, [this](bool checked) {
            if (checked) {
                q->header()->setSortIndicator(q->header()->sortIndicatorSection(), Qt::DescendingOrder);
            }
        });

        QObject::connect(q->header(), &QHeaderView::sectionClicked, q, [this](int index) {
            mSortColumnActionGroup.actions()[index]->setChecked(true);
            mSortDirectionActionGroup.actions()[q->header()->sortIndicatorOrder()]->setChecked(true);
        });
    }

    auto sortColumnActions = mSortColumnActionGroup.actions();
    for (QAction *action : std::as_const(sortColumnActions)) {
        const int column = action->data().toInt();
        action->setVisible(!q->isColumnHidden(column));
    }

    sortColumnActions[q->header()->sortIndicatorSection()]->setChecked(true);
    mSortDirectionActionGroup.actions()[q->header()->sortIndicatorOrder()]->setChecked(true);

    return mColumnSortingMenu;
}

void TreeViewPrivate::columnVisibilityActionTriggered(QAction *action)
{
    const int column = action->data().toInt();
    if (action->isChecked()) {
        q->showColumn(column);
        if (q->columnWidth(column) == 0 || q->columnWidth(column) == q->header()->defaultSectionSize()) {
            q->resizeColumnToContents(column);
            q->setColumnWidth(column, std::min(q->columnWidth(column), MAX_AUTOMATIC_COLUMN_WIDTH));
        }
    } else {
        q->hideColumn(column);
    }

    updateColumnVisibilityActions();
    if (mColumnSortingMenu) {
        mSortColumnActionGroup.actions()[column]->setVisible(!q->isColumnHidden(column));
    }

    saveColumnLayout();
}

bool TreeViewPrivate::eventFilter(QObject *watched, QEvent *event)
{
    Q_UNUSED(watched)
    if (event->type() == QEvent::ContextMenu) {
        auto e = static_cast<QContextMenuEvent *>(event);
        columnVisibilityMenu()->popup(q->mapToGlobal(e->pos()));

        return true;
    }

    return false;
}

void TreeViewPrivate::saveColumnLayout(const QString &stateGroupName)
{
    if (!stateGroupName.isEmpty()) {
        mStateGroupName = stateGroupName;
    }
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

bool TreeViewPrivate::restoreColumnLayout(const QString &stateGroupName)
{
    if (stateGroupName.isEmpty()) {
        return false;
    }
    mStateGroupName = stateGroupName;
    auto config = KConfigGroup(KSharedConfig::openStateConfig(), mStateGroupName);
    auto header = q->header();

    QVariantList columnVisibility = config.readEntry("ColumnVisibility", QVariantList());
    QVariantList columnOrder = config.readEntry("ColumnOrder", QVariantList());
    QVariantList columnWidths = config.readEntry("ColumnWidths", QVariantList());

    if (!columnVisibility.isEmpty() && !columnOrder.isEmpty() && !columnWidths.isEmpty()) {
        for (int i = 0; i < header->count(); ++i) {
            if (i >= columnOrder.size() || i >= columnWidths.size() || i >= columnVisibility.size()) {
                // An additional column that was not around last time we saved.
                // We default to hidden.
                q->hideColumn(i);
                continue;
            }
            bool visible = columnVisibility[i].toBool();
            int width = columnWidths[i].toInt();
            int order = columnOrder[i].toInt();

            header->resizeSection(i, width ? width : header->defaultSectionSize());
            header->moveSection(header->visualIndex(i), order);

            if (!visible) {
                q->hideColumn(i);
            }
        }
    }

    int sortOrder = config.readEntry("SortAscending", (int)Qt::AscendingOrder);
    int sortColumn = config.readEntry("SortColumn", q->isSortingEnabled() ? 0 : -1);
    if (sortColumn >= 0) {
        q->sortByColumn(sortColumn, (Qt::SortOrder)sortOrder);
    }

    QObject::connect(header, &QHeaderView::sectionResized, q, [this]() {
        saveColumnLayout();
    });
    QObject::connect(header, &QHeaderView::sectionMoved, q, [this]() {
        saveColumnLayout();
    });
    QObject::connect(header, &QHeaderView::sortIndicatorChanged, q, [this]() {
        saveColumnLayout();
    });
    return !columnVisibility.isEmpty() && !columnOrder.isEmpty() && !columnWidths.isEmpty();
}

void TreeViewPrivate::keyPressEvent(QKeyEvent *event)
{
    if (event == QKeySequence::Copy) {
        const QModelIndex index = q->currentIndex();
        if (index.isValid() && q->model()) {
            QVariant variant = q->model()->data(index, Kleo::ClipboardRole);
            if (!variant.isValid()) {
                variant = q->model()->data(index, Qt::DisplayRole);
            }
            if (variant.canConvert<QString>()) {
                QGuiApplication::clipboard()->setText(variant.toString());
            }
        }
        event->accept();
        return;
    }
}

void TreeViewPrivate::resizeToContentsLimited()
{
    for (int i = 0; i < q->model()->columnCount(); i++) {
        q->resizeColumnToContents(i);
        q->setColumnWidth(i, std::min(q->columnWidth(i), MAX_AUTOMATIC_COLUMN_WIDTH));
    }
}
