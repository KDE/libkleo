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

namespace
{
class TreeWidget : public QTreeWidget
{
    Q_OBJECT
public:
    using QTreeWidget::QTreeWidget;

protected:
    void focusInEvent(QFocusEvent *event) override
    {
        QTreeWidget::focusInEvent(event);
        // queue the invokation, so that it happens after the widget itself got focus
        QMetaObject::invokeMethod(this, &TreeWidget::forceAccessibleFocusEventForCurrentItem, Qt::QueuedConnection);
    }

private:
    void forceAccessibleFocusEventForCurrentItem()
    {
        // force Qt to send a focus event for the current item to accessibility
        // tools; otherwise, the user has no idea which item is selected when the
        // list gets keyboard input focus
        const auto current = currentItem();
        setCurrentItem(nullptr);
        setCurrentItem(current);
    }
};
}

class Kleo::DNAttributeOrderConfigWidget::DNAttributeOrderConfigWidgetPrivate
{
public:
    enum { Right = 0, Left = 1, UUp = 2, Up = 3, Down = 4, DDown = 5 };

    TreeWidget *availableLV = nullptr;
    TreeWidget *currentLV = nullptr;
    std::vector<QToolButton *> navTB;

    QTreeWidgetItem *placeHolderItem = nullptr;
};

static void prepare(QTreeWidget *lv)
{
    lv->setAllColumnsShowFocus(true);
    lv->header()->setStretchLastSection(true);
    lv->setHeaderLabels(QStringList() << QString() << i18n("Description"));
}

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
    auto availableAttributesLabel = new QLabel(i18n("Available attributes:"), this);
    glay->addWidget(availableAttributesLabel, row, 0);
    auto currentAttributesLabel = new QLabel(i18n("Current attribute order:"), this);
    glay->addWidget(currentAttributesLabel, row, 2);

    ++row;
    glay->setRowStretch(row, 1);

    d->availableLV = new TreeWidget(this);
    availableAttributesLabel->setBuddy(d->availableLV);
    d->availableLV->setAccessibleName(i18n("available attributes"));
    prepare(d->availableLV);
    d->availableLV->sortItems(0, Qt::AscendingOrder);
    glay->addWidget(d->availableLV, row, 0);

    d->placeHolderItem = new QTreeWidgetItem(d->availableLV);
    d->placeHolderItem->setText(0, QStringLiteral("_X_"));
    d->placeHolderItem->setText(1, i18n("All others"));
    d->placeHolderItem->setData(0, Qt::AccessibleTextRole, i18n("All others"));

    struct NavButtonInfo {
        const char *icon;
        const KLazyLocalizedString accessibleName;
        const KLazyLocalizedString tooltip;
        void (DNAttributeOrderConfigWidget::*slot)();
        bool autorepeat;
    };
    static const std::vector<NavButtonInfo> navButtons = {
        {
            "go-next",
            kli18nc("@action:button", "Add"),
            kli18n("Add to current attribute order"),
            &DNAttributeOrderConfigWidget::slotRightButtonClicked,
            false,
        },
        {
            "go-previous",
            kli18nc("@action:button", "Remove"),
            kli18n("Remove from current attribute order"),
            &DNAttributeOrderConfigWidget::slotLeftButtonClicked,
            false,
        },
        {
            "go-top",
            kli18nc("@action:button", "Move to Top"),
            kli18n("Move to top"),
            &DNAttributeOrderConfigWidget::slotDoubleUpButtonClicked,
            false,
        },
        {
            "go-up",
            kli18nc("@action:button", "Move Up"),
            kli18n("Move one up"),
            &DNAttributeOrderConfigWidget::slotUpButtonClicked,
            true,
        },
        {
            "go-down",
            kli18nc("@action:button", "Move Down"),
            kli18n("Move one down"),
            &DNAttributeOrderConfigWidget::slotDownButtonClicked,
            true,
        },
        {
            "go-bottom",
            kli18nc("@action:button", "Move to Bottom"),
            kli18n("Move to bottom"),
            &DNAttributeOrderConfigWidget::slotDoubleDownButtonClicked,
            false,
        },
    };

    const auto createToolButton = [this](const NavButtonInfo &navButton) {
        auto tb = new QToolButton{this};
        tb->setIcon(QIcon::fromTheme(QLatin1StringView(navButton.icon)));
        tb->setEnabled(false);
        tb->setAccessibleName(KLocalizedString{navButton.accessibleName}.toString());
        tb->setToolTip(KLocalizedString(navButton.tooltip).toString());
        tb->setAutoRepeat(navButton.autorepeat);
        connect(tb, &QToolButton::clicked, this, navButton.slot);
        d->navTB.push_back(tb);
        return tb;
    };

    {
        auto buttonCol = new QVBoxLayout;
        buttonCol->addStretch();
        buttonCol->addWidget(createToolButton(navButtons[DNAttributeOrderConfigWidgetPrivate::Right]));
        buttonCol->addWidget(createToolButton(navButtons[DNAttributeOrderConfigWidgetPrivate::Left]));
        buttonCol->addStretch();

        glay->addLayout(buttonCol, row, 1);
    }

    d->currentLV = new TreeWidget(this);
    currentAttributesLabel->setBuddy(d->currentLV);
    d->currentLV->setAccessibleName(i18n("current attribute order"));
    prepare(d->currentLV);
    glay->addWidget(d->currentLV, row, 2);

    {
        auto buttonCol = new QVBoxLayout;
        buttonCol->addStretch();
        buttonCol->addWidget(createToolButton(navButtons[DNAttributeOrderConfigWidgetPrivate::UUp]));
        buttonCol->addWidget(createToolButton(navButtons[DNAttributeOrderConfigWidgetPrivate::Up]));
        buttonCol->addWidget(createToolButton(navButtons[DNAttributeOrderConfigWidgetPrivate::Down]));
        buttonCol->addWidget(createToolButton(navButtons[DNAttributeOrderConfigWidgetPrivate::DDown]));
        buttonCol->addStretch();

        glay->addLayout(buttonCol, row, 3);
    }

#ifndef NDEBUG
    Q_ASSERT(d->navTB.size() == navButtons.size());
    for (uint i = 0; i < navButtons.size(); ++i) {
        Q_ASSERT(d->navTB[i]->accessibleName() == KLocalizedString{navButtons[i].accessibleName}.toString());
    }
#endif

    connect(d->availableLV, &QTreeWidget::itemSelectionChanged, this, &DNAttributeOrderConfigWidget::slotAvailableSelectionChanged);
    connect(d->currentLV, &QTreeWidget::itemSelectionChanged, this, &DNAttributeOrderConfigWidget::slotCurrentOrderSelectionChanged);
}

Kleo::DNAttributeOrderConfigWidget::~DNAttributeOrderConfigWidget() = default;

void Kleo::DNAttributeOrderConfigWidget::setAttributeOrder(const QStringList &order)
{
    // save the _X_ item:
    takePlaceHolderItem();
    // clear the rest:
    d->availableLV->clear();
    d->currentLV->clear();

    // fill the RHS listview:
    QTreeWidgetItem *last = nullptr;
    for (const auto &entry : order) {
        const QString attr = entry.toUpper();
        if (attr == QLatin1StringView("_X_")) {
            takePlaceHolderItem();
            d->currentLV->insertTopLevelItem(d->currentLV->topLevelItemCount(), d->placeHolderItem);
            last = d->placeHolderItem;
        } else {
            last = new QTreeWidgetItem(d->currentLV, last);
            last->setText(0, attr);
            const auto label = DN::attributeNameToLabel(attr);
            last->setText(1, label);
            const QString accessibleName = label + QLatin1StringView(", ") + attr;
            last->setData(0, Qt::AccessibleTextRole, accessibleName);
        }
    }
    d->currentLV->setCurrentItem(d->currentLV->topLevelItem(0));

    // fill the LHS listview with what's left:

    const QStringList all = DN::attributeNames();
    for (const auto &attr : all) {
        if (!order.contains(attr, Qt::CaseInsensitive)) {
            auto item = new QTreeWidgetItem(d->availableLV);
            item->setText(0, attr);
            const auto label = DN::attributeNameToLabel(attr);
            item->setText(1, label);
            const QString accessibleName = label + QLatin1StringView(", ") + attr;
            item->setData(0, Qt::AccessibleTextRole, accessibleName);
        }
    }

    if (!d->placeHolderItem->treeWidget()) {
        d->availableLV->addTopLevelItem(d->placeHolderItem);
    }
    d->availableLV->setCurrentItem(d->availableLV->topLevelItem(0));
}

void Kleo::DNAttributeOrderConfigWidget::takePlaceHolderItem()
{
    if (QTreeWidget *lv = d->placeHolderItem->treeWidget()) {
        lv->takeTopLevelItem(lv->indexOfTopLevelItem(d->placeHolderItem));
    }
}

QStringList Kleo::DNAttributeOrderConfigWidget::attributeOrder() const
{
    QStringList order;
    for (QTreeWidgetItemIterator it(d->currentLV); (*it); ++it) {
        order.push_back((*it)->text(0));
    }
    return order;
}

void Kleo::DNAttributeOrderConfigWidget::slotAvailableSelectionChanged()
{
    d->navTB[DNAttributeOrderConfigWidgetPrivate::Right]->setEnabled(!d->availableLV->selectedItems().empty());
}

void Kleo::DNAttributeOrderConfigWidget::slotCurrentOrderSelectionChanged()
{
    const auto selectedItems = d->currentLV->selectedItems();
    auto selectedItem = selectedItems.empty() ? nullptr : selectedItems.front();
    enableDisableButtons(selectedItem);
}

void Kleo::DNAttributeOrderConfigWidget::enableDisableButtons(QTreeWidgetItem *item)
{
    d->navTB[DNAttributeOrderConfigWidgetPrivate::UUp]->setEnabled(item && d->currentLV->itemAbove(item));
    d->navTB[DNAttributeOrderConfigWidgetPrivate::Up]->setEnabled(item && d->currentLV->itemAbove(item));
    d->navTB[DNAttributeOrderConfigWidgetPrivate::Left]->setEnabled(item);
    d->navTB[DNAttributeOrderConfigWidgetPrivate::Down]->setEnabled(item && d->currentLV->itemBelow(item));
    d->navTB[DNAttributeOrderConfigWidgetPrivate::DDown]->setEnabled(item && d->currentLV->itemBelow(item));
}

void Kleo::DNAttributeOrderConfigWidget::slotUpButtonClicked()
{
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
    d->currentLV->setCurrentItem(item);
    enableDisableButtons(item);
    Q_EMIT changed();
}

void Kleo::DNAttributeOrderConfigWidget::slotDoubleUpButtonClicked()
{
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
    d->currentLV->setCurrentItem(item);
    enableDisableButtons(item);
    Q_EMIT changed();
}

void Kleo::DNAttributeOrderConfigWidget::slotDownButtonClicked()
{
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
    d->currentLV->setCurrentItem(item);
    enableDisableButtons(item);
    Q_EMIT changed();
}

void Kleo::DNAttributeOrderConfigWidget::slotDoubleDownButtonClicked()
{
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
    d->currentLV->setCurrentItem(item);
    enableDisableButtons(item);
    Q_EMIT changed();
}

void Kleo::DNAttributeOrderConfigWidget::slotLeftButtonClicked()
{
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
    d->availableLV->setCurrentItem(right);
    if (next) {
        d->currentLV->setCurrentItem(next);
    }
    enableDisableButtons(next);
    Q_EMIT changed();
}

void Kleo::DNAttributeOrderConfigWidget::slotRightButtonClicked()
{
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
    }
    d->currentLV->insertTopLevelItem(newRightIndex, left);
    d->currentLV->setCurrentItem(left);
    enableDisableButtons(left);
    d->navTB[DNAttributeOrderConfigWidgetPrivate::Right]->setEnabled(next);
    if (next) {
        d->availableLV->setCurrentItem(next);
    }
    Q_EMIT changed();
}

void Kleo::DNAttributeOrderConfigWidget::virtual_hook(int, void *)
{
}

#include "dnattributeorderconfigwidget.moc"

#include "moc_dnattributeorderconfigwidget.cpp"
