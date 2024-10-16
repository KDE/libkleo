/* -*- mode: c++; c-basic-offset:4 -*-
    ui/adjustingscrollarea.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QScrollArea>

namespace Kleo
{

/**
 * This class improves a few aspects of QScrollArea for usage by us, in
 * particular, for vertically scrollable widgets.
 *
 * If sizeAdjustPolicy is set to QAbstractScrollArea::AdjustToContents,
 * then the scroll area will (try to) adjust its size to the widget to avoid
 * scroll bars as much as possible.
 */
class KLEO_EXPORT AdjustingScrollArea : public QScrollArea
{
    Q_OBJECT

public:
    /**
     * Creates a scroll area with a QWidget with QVBoxLayout that is flagged
     * as resizable.
     */
    explicit AdjustingScrollArea(QWidget *parent = nullptr);
    ~AdjustingScrollArea() override;

    /**
     * Reimplemented to add the minimum size hint of the widget.
     */
    QSize minimumSizeHint() const override;

    /**
     * Reimplemented to remove the caching of the size/size hint of the
     * widget and to add the horizontal size hint of the vertical scroll bar
     * unless it is explicitly turned off.
     */
    QSize sizeHint() const override;

private:
    void adjustSizeOfWindowBy(const QSize &extent);
    bool eventFilter(QObject *obj, QEvent *ev) override;
};

}
