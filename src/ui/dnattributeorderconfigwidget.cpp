/*  -*- c++ -*-
    dnattributeorderconfigwidget.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "dnattributeorderconfigwidget.h"
#include "libkleo_debug.h"
#include "libkleo/dn.h"

#include <KLocalizedString>
#include <QIcon>

#include <QToolButton>
#include <QGridLayout>
#include <QLabel>

#include <QTreeWidget>
#include <QHeaderView>


class Kleo::DNAttributeOrderConfigWidget::Private
{
public:
    enum { UUp = 0, Up = 1, Left = 2, Right = 3, Down = 4, DDown = 5 };

#ifndef QT_NO_TREEWIDGET
    QTreeWidget *availableLV = nullptr;
    QTreeWidget *currentLV = nullptr;
#endif
    QToolButton *navTB[6];

#ifndef QT_NO_TREEWIDGET
    QTreeWidgetItem *placeHolderItem = nullptr;
#endif

    Kleo::DNAttributeMapper *mapper = nullptr;
};

#ifndef QT_NO_TREEWIDGET
static void prepare(QTreeWidget *lv)
{
    lv->setAllColumnsShowFocus(true);
    lv->header()->setStretchLastSection(true);
    lv->setHeaderLabels(QStringList() << QString() << i18n("Description"));
}
#endif

Kleo::DNAttributeOrderConfigWidget::DNAttributeOrderConfigWidget(DNAttributeMapper *mapper, QWidget *parent, Qt::WindowFlags f)
    : QWidget(parent, f), d(new Private)
{
    Q_ASSERT(mapper);
    d->mapper = mapper;

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

    static const struct {
        const char *icon;
        int row, col;
        const char *tooltip;
        void(DNAttributeOrderConfigWidget::*slot)();
        bool autorepeat;
    } navButtons[] = {
        { "go-top",    0, 1, I18N_NOOP("Move to top"),   &DNAttributeOrderConfigWidget::slotDoubleUpButtonClicked, false },
        { "go-up",    1, 1, I18N_NOOP("Move one up"),    &DNAttributeOrderConfigWidget::slotUpButtonClicked, true },
        { "go-previous",  2, 0, I18N_NOOP("Remove from current attribute order"), &DNAttributeOrderConfigWidget::slotLeftButtonClicked, false },
        { "go-next", 2, 2, I18N_NOOP("Add to current attribute order"), &DNAttributeOrderConfigWidget::slotRightButtonClicked, false },
        { "go-down",  3, 1, I18N_NOOP("Move one down"),  &DNAttributeOrderConfigWidget::slotDownButtonClicked, true },
        { "go-bottom",  4, 1, I18N_NOOP("Move to bottom"), &DNAttributeOrderConfigWidget::slotDoubleDownButtonClicked, false }
    };

    for (unsigned int i = 0; i < sizeof navButtons / sizeof * navButtons; ++i) {
        QToolButton *tb = d->navTB[i] = new QToolButton(this);
        tb->setIcon(QIcon::fromTheme(QLatin1String(navButtons[i].icon)));
        tb->setEnabled(false);
        tb->setToolTip(i18n(navButtons[i].tooltip));
        xlay->addWidget(tb, navButtons[i].row, navButtons[i].col);
        tb->setAutoRepeat(navButtons[i].autorepeat);
        connect(tb, &QToolButton::clicked, this, navButtons[i].slot);
    }

    glay->addLayout(xlay, row, 1);
}

Kleo::DNAttributeOrderConfigWidget::~DNAttributeOrderConfigWidget()
{
    delete d;
}

void Kleo::DNAttributeOrderConfigWidget::load()
{
#ifndef QT_NO_TREEWIDGET
    // save the _X_ item:
    takePlaceHolderItem();
    // clear the rest:
    d->availableLV->clear();
    d->currentLV->clear();

    const QStringList order = d->mapper->attributeOrder();

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
            last->setText(1, d->mapper->name2label(attr));
        }
    }

    // fill the LHS listview with what's left:

    const QStringList all = Kleo::DNAttributeMapper::instance()->names();
    const QStringList::const_iterator end(all.end());
    for (QStringList::const_iterator it = all.begin(); it != end; ++it) {
        if (!order.contains(*it)) {
            auto item = new QTreeWidgetItem(d->availableLV);
            item->setText(0, *it);
            item->setText(1, d->mapper->name2label(*it));
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

void Kleo::DNAttributeOrderConfigWidget::save() const
{
#ifndef QT_NO_TREEWIDGET
    QStringList order;
    for (QTreeWidgetItemIterator it(d->currentLV); (*it); ++it) {
        order.push_back((*it)->text(0));
    }

    d->mapper->setAttributeOrder(order);
#endif
}

void Kleo::DNAttributeOrderConfigWidget::defaults()
{
     qCDebug (LIBKLEO_LOG) << "Sorry, not implemented: Kleo::DNAttributeOrderConfigWidget::defaults()";
}

void Kleo::DNAttributeOrderConfigWidget::slotAvailableSelectionChanged(QTreeWidgetItem *item)
{
    d->navTB[Private::Right]->setEnabled(item);
}

void Kleo::DNAttributeOrderConfigWidget::slotCurrentOrderSelectionChanged(QTreeWidgetItem *item)
{
    enableDisableButtons(item);
}

void Kleo::DNAttributeOrderConfigWidget::enableDisableButtons(QTreeWidgetItem *item)
{
#ifndef QT_NO_TREEWIDGET
    d->navTB[Private::UUp  ]->setEnabled(item && d->currentLV->itemAbove(item));
    d->navTB[Private::Up   ]->setEnabled(item && d->currentLV->itemAbove(item));
    d->navTB[Private::Left ]->setEnabled(item);
    d->navTB[Private::Down ]->setEnabled(item && d->currentLV->itemBelow(item));
    d->navTB[Private::DDown]->setEnabled(item && d->currentLV->itemBelow(item));
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
    d->navTB[Private::Right]->setEnabled(next);
    if (next) {
        next->setSelected(true);
    }
    Q_EMIT changed();
#endif
}

void Kleo::DNAttributeOrderConfigWidget::virtual_hook(int, void *) {}

