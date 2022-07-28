/*
    ui/navigatabletreewidget.h

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
 * A tree view that allows extended keyboard navigation.
 *
 * The NavigatableTreeWidget allows column by column keyboard navigation even if
 * the selection behavior is set to SelectRows. Column by column navigation is
 * required to make a tree view accessible.
 */
class KLEO_EXPORT NavigatableTreeWidget : public QTreeWidget
{
    Q_OBJECT
public:
    using QTreeWidget::QTreeWidget;

protected:
    QModelIndex moveCursor(QAbstractItemView::CursorAction cursorAction, Qt::KeyboardModifiers modifiers) override;
};

}
