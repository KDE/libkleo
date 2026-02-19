/*
    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2026 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "treeview.h"

#include <QActionGroup>

namespace Kleo
{

class TreeViewPrivate
{
    QTreeView *q;

public:
    static constexpr int MAX_AUTOMATIC_COLUMN_WIDTH = 400;

    explicit TreeViewPrivate(QTreeView *q);
    ~TreeViewPrivate();

    bool eventFilter(QObject *watched, QEvent *event);
    void saveColumnLayout(const QString &stateGroupName = {});
    bool restoreColumnLayout(const QString &stateGroupName);

    QMenu *columnVisibilityMenu();
    QMenu *columnSortingMenu();

    void keyPressEvent(QKeyEvent *event);
    void resizeToContentsLimited();

private:
    void updateColumnVisibilityActions();
    void columnVisibilityActionTriggered(QAction *action);

    QString mStateGroupName;
    QMenu *mColumnVisibilityMenu = nullptr;
    QMenu *mColumnSortingMenu = nullptr;
    QActionGroup mSortColumnActionGroup;
    QActionGroup mSortDirectionActionGroup;
};

}
