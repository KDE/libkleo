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
 * A tree widget that allows accessible column by column keyboard navigation.
 *
 * This is the QTreeWidget-derived variant of NavigatableTreeView.
 *
 * \sa NavigatableTreeView
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
