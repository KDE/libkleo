/* -*- mode: c++; c-basic-offset:4 -*-
    utils/adjustingscrollarea.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "adjustingscrollarea.h"

#include <QApplication>
#include <QResizeEvent>
#include <QScreen>
#include <QScrollBar>
#include <QVBoxLayout>

using namespace Kleo;

AdjustingScrollArea::AdjustingScrollArea(QWidget *parent)
    : QScrollArea{parent}
{
    auto w = new QWidget;
    w->setObjectName(QLatin1String("scrollarea_widget"));
    new QVBoxLayout{w};
    setWidget(w);
    setWidgetResizable(true);
    w->installEventFilter(this);

    connect(qApp, &QApplication::focusChanged, this, [this](QWidget *old, QWidget *now) {
        Q_UNUSED(old);
        ensureWidgetVisible(now);
    });
}

AdjustingScrollArea::~AdjustingScrollArea()
{
    widget()->removeEventFilter(this);
}

QSize AdjustingScrollArea::minimumSizeHint() const
{
    const int fw = frameWidth();
    QSize sz{2 * fw, 2 * fw};
    sz += {widget()->minimumSizeHint().width(), 0};
    if (verticalScrollBarPolicy() != Qt::ScrollBarAlwaysOff) {
        sz.setWidth(sz.width() + verticalScrollBar()->sizeHint().width());
    }
    if (horizontalScrollBarPolicy() != Qt::ScrollBarAlwaysOff) {
        sz.setHeight(sz.height() + horizontalScrollBar()->sizeHint().height());
    }
    return QScrollArea::minimumSizeHint().expandedTo(sz);
}

QSize AdjustingScrollArea::sizeHint() const
{
    const int fw = frameWidth();
    QSize sz{2 * fw, 2 * fw};
    sz += viewportSizeHint();
    if (verticalScrollBarPolicy() != Qt::ScrollBarAlwaysOff) {
        sz.setWidth(sz.width() + verticalScrollBar()->sizeHint().width());
    }
    if (horizontalScrollBarPolicy() != Qt::ScrollBarAlwaysOff) {
        sz.setHeight(sz.height() + horizontalScrollBar()->sizeHint().height());
    }
    sz = QScrollArea::sizeHint().expandedTo(sz);
    return sz;
}

void AdjustingScrollArea::adjustSizeOfWindowBy(const QSize &extent)
{
    if (auto w = window()) {
        const auto currentSize = w->size();
        // we limit the automatic size adjustment to 2/3 of the screen's size
        const auto maxWindowSize = screen()->geometry().size() * 2 / 3;
        const auto newWindowSize = currentSize.expandedTo((currentSize + extent).boundedTo(maxWindowSize));
        if (newWindowSize != currentSize) {
            w->resize(newWindowSize);
        }
    }
}

bool AdjustingScrollArea::eventFilter(QObject *obj, QEvent *ev)
{
    if (ev->type() == QEvent::Resize && obj == widget() && sizeAdjustPolicy() == AdjustToContents) {
        const auto *const event = static_cast<QResizeEvent *>(ev);
        if (event->size().height() > event->oldSize().height()) {
            const auto currentViewportHeight = viewport()->height();
            const auto wantedViewportHeight = event->size().height();
            const auto wantedAdditionalHeight = wantedViewportHeight - currentViewportHeight;
            if (wantedAdditionalHeight > 0) {
                adjustSizeOfWindowBy(QSize{0, wantedAdditionalHeight});
            }
        }
    }
    return QScrollArea::eventFilter(obj, ev);
}
