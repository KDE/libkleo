/*  -*- c++ -*-
    dnattributeorderconfigwidget.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "dnattributeorderconfigwidget.h"

#include <libkleo/dn.h>

#include <libkleo_debug.h>

#include <KLazyLocalizedString>
#include <KLocalizedString>

#include <QGridLayout>
#include <QHeaderView>
#include <QIcon>
#include <QLabel>
#include <QToolButton>
#include <QTreeWidget>

class Kleo::DNAttributeOrderConfigWidget::DNAttributeOrderConfigWidgetPrivate
{
public:
    enum { UUp = 0, Up = 1, Left = 2, Right = 3, Down = 4, DDown = 5 };

#ifndef QT_NO_TREEWIDGET
    QTreeWidget *availableLV = nullptr;
    QTreeWidget *currentLV = nullptr;
#endif
    std::vector<QToolButton *> navTB;

#ifndef QT_NO_TREEWIDGET
    QTreeWidgetItem *placeHolderItem = nullptr;
#endif
};

#ifndef QT_NO_TREEWIDGET
static void prepare(QTreeWidget *lv)
{
    lv->setAllColumnsShowFocus(true);
    lv->header()->setStretchLastSection(true);
    lv->setHeaderLabels(QStringList() << QString() << i18n("Description"));
}
#endif

Kleo::DNAttributeOrderConfigWidget::DNAttributeOrderConfigWidget(QWidget *parent, Qt::WindowFlags f)
    : QWidget(parent, f)
    , d(new DNAttributeOrderConfigWidgetPrivate)
{
    auto glay = new QGridLayout(this);
    glay->setContentsMargins(0, 0, 0, 0);
    glay->setColumnStretch(0, 1);
    glay->setColumnStretch(2, 1);

    int row = -1;

    ++row;
    glay->addWidget(new QLabel(i18n("Available attributes:"), this), row, 0);
    glay->addWidget(new QLabel(i18n("Current attribute order:"), this), row, 2);

    ++row;
    glay->setRowStretch(row, 1);

#ifndef QT_NO_TREEWIDGET
    d->availableLV = new QTreeWidget(this);
    prepare(d->availableLV);
    d->availableLV->sortItems(0, Qt::AscendingOrder);
    glay->addWidget(d->availableLV, row, 0);

    d->currentLV = new QTreeWidget(this);
    prepare(d->currentLV);
    glay->addWidget(d->currentLV, row, 2);

    connect(d->availableLV, &QTreeWidget::itemClicked, this, &DNAttributeOrderConfigWidget::slotAvailableSelectionChanged);
    connect(d->currentLV, &QTreeWidget::itemClicked, this, &DNAttributeOrderConfigWidget::slotCurrentOrderSelectionChanged);

    d->placeHolderItem = new QTreeWidgetItem(d->availableLV);
    d->placeHolderItem->setText(0, QStringLiteral("_X_"));
    d->placeHolderItem->setText(1, i18n("All others"));
#endif

    // the up/down/left/right arrow cross:

    auto xlay = new QGridLayout();
    xlay->setSpacing(0);
    xlay->setObjectName(QStringLiteral("xlay"));
    xlay->setAlignment(Qt::AlignCenter);

    struct NavButtonInfo {
        const char *icon;
        int row, col;
        const KLazyLocalizedString tooltip;
        void (DNAttributeOrderConfigWidget::*slot)();
        bool autorepeat;
    };
    static const std::vector<NavButtonInfo> navButtons = {
        {"go-top", 0, 1, kli18n("Move to top"), &DNAttributeOrderConfigWidget::slotDoubleUpButtonClicked, false},
        {"go-up", 1, 1, kli18n("Move one up"), &DNAttributeOrderConfigWidget::slotUpButtonClicked, true},
        {"go-previous", 2, 0, kli18n("Remove from current attribute order"), &DNAttributeOrderConfigWidget::slotLeftButtonClicked, false},
        {"go-next", 2, 2, kli18n("Add to current attribute order"), &DNAttributeOrderConfigWidget::slotRightButtonClicked, false},
        {"go-down", 3, 1, kli18n("Move one down"), &DNAttributeOrderConfigWidget::slotDownButtonClicked, true},
        {"go-bottom", 4, 1, kli18n("Move to bottom"), &DNAttributeOrderConfigWidget::slotDoubleDownButtonClicked, false},
    };

    for (const auto &navButton : navButtons) {
        auto tb = new QToolButton{this};
        tb->setIcon(QIcon::fromTheme(QLatin1String(navButton.icon)));
        tb->setEnabled(false);
        tb->setToolTip(KLocalizedString(navButton.tooltip).toString());
        xlay->addWidget(tb, navButton.row, navButton.col);
        tb->setAutoRepeat(navButton.autorepeat);
        connect(tb, &QToolButton::clicked, this, navButton.slot);
        d->navTB.push_back(tb);
    }

    glay->addLayout(xlay, row, 1);
}

Kleo::DNAttributeOrderConfigWidget::~DNAttributeOrderConfigWidget() = default;

void Kleo::DNAttributeOrderConfigWidget::setAttributeOrder(const QStringList &order)
{
#ifndef QT_NO_TREEWIDGET
    // save the _X_ item:
    takePlaceHolderItem();
    // clear the rest:
    d->availableLV->clear();
    d->currentLV->clear();

    // fill the RHS listview:
    QTreeWidgetItem *last = nullptr;
    for (QStringList::const_iterator it = order.begin(); it != order.end(); ++it) {
        const QString attr = (*it).toUpper();
        if (attr == QLatin1String("_X_")) {
            takePlaceHolderItem();
            d->currentLV->insertTopLevelItem(d->currentLV->topLevelItemCount(), d->placeHolderItem);
            last = d->placeHolderItem;
        } else {
            last = new QTreeWidgetItem(d->currentLV, last);
            last->setText(0, attr);
            last->setText(1, DN::attributeNameToLabel(attr));
        }
    }

    // fill the LHS listview with what's left:

    const QStringList all = DN::attributeNames();
    const QStringList::const_iterator end(all.end());
    for (QStringList::const_iterator it = all.begin(); it != end; ++it) {
        if (!order.contains(*it)) {
            auto item = new QTreeWidgetItem(d->availableLV);
            item->setText(0, *it);
            item->setText(1, DN::attributeNameToLabel(*it));
        }
    }

    if (!d->placeHolderItem->treeWidget()) {
        d->availableLV->addTopLevelItem(d->placeHolderItem);
    }
#endif
}

void Kleo::DNAttributeOrderConfigWidget::takePlaceHolderItem()
{
#ifndef QT_NO_TREEWIDGET
    if (QTreeWidget *lv = d->placeHolderItem->treeWidget()) {
        lv->takeTopLevelItem(lv->indexOfTopLevelItem(d->placeHolderItem));
    }
#endif
}

QStringList Kleo::DNAttributeOrderConfigWidget::attributeOrder() const
{
    QStringList order;
#ifndef QT_NO_TREEWIDGET
    for (QTreeWidgetItemIterator it(d->currentLV); (*it); ++it) {
        order.push_back((*it)->text(0));
    }
#endif
    return order;
}

void Kleo::DNAttributeOrderConfigWidget::slotAvailableSelectionChanged(QTreeWidgetItem *item)
{
    d->navTB[DNAttributeOrderConfigWidgetPrivate::Right]->setEnabled(item);
}

void Kleo::DNAttributeOrderConfigWidget::slotCurrentOrderSelectionChanged(QTreeWidgetItem *item)
{
    enableDisableButtons(item);
}

void Kleo::DNAttributeOrderConfigWidget::enableDisableButtons(QTreeWidgetItem *item)
{
#ifndef QT_NO_TREEWIDGET
    d->navTB[DNAttributeOrderConfigWidgetPrivate::UUp]->setEnabled(item && d->currentLV->itemAbove(item));
    d->navTB[DNAttributeOrderConfigWidgetPrivate::Up]->setEnabled(item && d->currentLV->itemAbove(item));
    d->navTB[DNAttributeOrderConfigWidgetPrivate::Left]->setEnabled(item);
    d->navTB[DNAttributeOrderConfigWidgetPrivate::Down]->setEnabled(item && d->currentLV->itemBelow(item));
    d->navTB[DNAttributeOrderConfigWidgetPrivate::DDown]->setEnabled(item && d->currentLV->itemBelow(item));
#endif
}

void Kleo::DNAttributeOrderConfigWidget::slotUpButtonClicked()
{
#ifndef QT_NO_TREEWIDGET
    if (d->currentLV->selectedItems().isEmpty()) {
        return;
    }
    QTreeWidgetItem *item = d->currentLV->selectedItems().first();
    int itemIndex = d->currentLV->indexOfTopLevelItem(item);
    if (itemIndex <= 0) {
        return;
    }
    d->currentLV->takeTopLevelItem(itemIndex);
    d->currentLV->insertTopLevelItem(itemIndex - 1, item);
    d->currentLV->clearSelection();
    item->setSelected(true);
    enableDisableButtons(item);
    Q_EMIT changed();
#endif
}

void Kleo::DNAttributeOrderConfigWidget::slotDoubleUpButtonClicked()
{
#ifndef QT_NO_TREEWIDGET
    if (d->currentLV->selectedItems().isEmpty()) {
        return;
    }
    QTreeWidgetItem *item = d->currentLV->selectedItems().first();
    int itemIndex = d->currentLV->indexOfTopLevelItem(item);
    if (itemIndex == 0) {
        return;
    }
    d->currentLV->takeTopLevelItem(itemIndex);
    d->currentLV->insertTopLevelItem(0, item);
    d->currentLV->clearSelection();
    item->setSelected(true);
    enableDisableButtons(item);
    Q_EMIT changed();
#endif
}

void Kleo::DNAttributeOrderConfigWidget::slotDownButtonClicked()
{
#ifndef QT_NO_TREEWIDGET
    if (d->currentLV->selectedItems().isEmpty()) {
        return;
    }
    QTreeWidgetItem *item = d->currentLV->selectedItems().first();
    int itemIndex = d->currentLV->indexOfTopLevelItem(item);
    if (itemIndex + 1 >= d->currentLV->topLevelItemCount()) {
        return;
    }
    d->currentLV->takeTopLevelItem(itemIndex);
    d->currentLV->insertTopLevelItem(itemIndex + 1, item);
    d->currentLV->clearSelection();
    item->setSelected(true);
    enableDisableButtons(item);
    Q_EMIT changed();
#endif
}

void Kleo::DNAttributeOrderConfigWidget::slotDoubleDownButtonClicked()
{
#ifndef QT_NO_TREEWIDGET
    if (d->currentLV->selectedItems().isEmpty()) {
        return;
    }
    QTreeWidgetItem *item = d->currentLV->selectedItems().first();
    const int itemIndex = d->currentLV->indexOfTopLevelItem(item);
    if (itemIndex + 1 >= d->currentLV->topLevelItemCount()) {
        return;
    }
    d->currentLV->takeTopLevelItem(itemIndex);
    d->currentLV->addTopLevelItem(item);
    d->currentLV->clearSelection();
    item->setSelected(true);
    enableDisableButtons(item);
    Q_EMIT changed();
#endif
}

void Kleo::DNAttributeOrderConfigWidget::slotLeftButtonClicked()
{
#ifndef QT_NO_TREEWIDGET
    if (d->currentLV->selectedItems().isEmpty()) {
        return;
    }
    QTreeWidgetItem *right = d->currentLV->selectedItems().first();
    QTreeWidgetItem *next = d->currentLV->itemBelow(right);
    if (!next) {
        next = d->currentLV->itemAbove(right);
    }
    d->currentLV->takeTopLevelItem(d->currentLV->indexOfTopLevelItem(right));
    d->availableLV->addTopLevelItem(right);
    d->availableLV->sortItems(0, Qt::AscendingOrder);
    if (next) {
        next->setSelected(true);
    }
    enableDisableButtons(next);
    Q_EMIT changed();
#endif
}

void Kleo::DNAttributeOrderConfigWidget::slotRightButtonClicked()
{
#ifndef QT_NO_TREEWIDGET
    if (d->availableLV->selectedItems().isEmpty()) {
        return;
    }
    QTreeWidgetItem *left = d->availableLV->selectedItems().first();
    QTreeWidgetItem *next = d->availableLV->itemBelow(left);
    if (!next) {
        next = d->availableLV->itemAbove(left);
    }
    d->availableLV->takeTopLevelItem(d->availableLV->indexOfTopLevelItem(left));
    int newRightIndex = d->currentLV->topLevelItemCount();
    if (!d->currentLV->selectedItems().isEmpty()) {
        QTreeWidgetItem *right = d->currentLV->selectedItems().first();
        newRightIndex = d->currentLV->indexOfTopLevelItem(right);
        right->setSelected(false);
    }
    d->currentLV->insertTopLevelItem(newRightIndex, left);
    left->setSelected(true);
    enableDisableButtons(left);
    d->navTB[DNAttributeOrderConfigWidgetPrivate::Right]->setEnabled(next);
    if (next) {
        next->setSelected(true);
    }
    Q_EMIT changed();
#endif
}

void Kleo::DNAttributeOrderConfigWidget::virtual_hook(int, void *)
{
}
