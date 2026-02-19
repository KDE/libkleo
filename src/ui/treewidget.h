/*
    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QTreeWidget>

namespace Kleo
{

/**
 * A tree widget that allows accessible column by column keyboard navigation
 * and that has customizable columns through a context menu in the header.
 *
 * This is the QTreeWidget-derived variant of TreeView.
 *
 * \sa TreeView
 */
class KLEO_EXPORT TreeWidget : public QTreeWidget
{
    Q_OBJECT
public:
    explicit TreeWidget(QWidget *parent = nullptr);
    ~TreeWidget() override;

    /**
     * Restores the layout state under key @p stateGroupName and enables state
     * saving when the object is destroyed. Make sure that @p stateGroupName is
     * unique for each place the widget occurs. Returns true if some state was
     * restored. If false is returned, no state was restored and the caller should
     * apply the default configuration.
     */
    bool restoreColumnLayout(const QString &stateGroupName);
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
    std::unique_ptr<Private> const d;
};

}
