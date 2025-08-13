/*
    ui/treeview.h

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QTreeView>

namespace Kleo
{

/**
 * A tree view that allows accessible column by column keyboard navigation
 * and that has customizable columns through a context menu in the header.
 *
 * Column by column navigation is required to make a tree view accessible.
 *
 * The TreeView allows column by column keyboard navigation even if
 * the selection behavior is set to SelectRows and users can expand/collapse
 * list items. To achieve this it deactivates the standard behavior of QTreeView
 * to expand/collapse items if the left/right arrow keys are used.
 *
 * Additionally, you may want to disable parent-child navigation in tree views
 * with left/right arrow keys because this also interferes with column by column
 * navigation. You can do this by setting
 * "QTreeView { arrow-keys-navigate-into-children: 0; }"
 * as application style sheet.
 *
 * \sa TreeWidget
 */
class KLEO_EXPORT TreeView : public QTreeView
{
    Q_OBJECT
public:
    explicit TreeView(QWidget *parent = nullptr);
    ~TreeView() override;

    /**
     * Restores the layout state under key @p stateGroupName and enables state
     * saving when the object is destroyed. Make sure that @p stateGroupName is
     * unique for each place the widget occurs. Returns true if some state was
     * restored. If false is returned, no state was restored and the caller should
     * apply the default configuration.
     */
    bool restoreColumnLayout(const QString &stateGroupName);

    /**
     * Set the state config group name to use for saving the state. Only needs
     * to be done if the state should be saged, but was not previously loaded
     * using TreeView::restoreColumnLayout.
     */
    void saveColumnLayout(const QString &stateGroupName);
    void resizeToContentsLimited();
Q_SIGNALS:
    void columnEnabled(int column);
    void columnDisabled(int column);

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

    void focusInEvent(QFocusEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;

    QModelIndex moveCursor(QAbstractItemView::CursorAction cursorAction, Qt::KeyboardModifiers modifiers) override;

private:
    class Private;
    const std::unique_ptr<Private> d;
};
}
