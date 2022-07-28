/*
    ui/navigatabletreeview.h

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
 * A tree view that allows accessible column by column keyboard navigation.
 *
 * Column by column navigation is required to make a tree view accessible.
 *
 * The NavigatableTreeView allows column by column keyboard navigation even if
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
 * \sa NavigatableTreeWidget
 */
class KLEO_EXPORT NavigatableTreeView : public QTreeView
{
    Q_OBJECT
public:
    using QTreeView::QTreeView;

protected:
    QModelIndex moveCursor(QAbstractItemView::CursorAction cursorAction, Qt::KeyboardModifiers modifiers) override;
};

}
