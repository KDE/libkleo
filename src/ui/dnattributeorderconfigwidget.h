/*  -*- c++ -*-
    dnattributeorderconfigwidget.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QWidget>

class QTreeWidgetItem;

namespace Kleo
{

class KLEO_EXPORT DNAttributeOrderConfigWidget : public QWidget
{
    Q_OBJECT
public:
    explicit DNAttributeOrderConfigWidget(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~DNAttributeOrderConfigWidget() override;

    QStringList attributeOrder() const;
    void setAttributeOrder(const QStringList &order);

Q_SIGNALS:
    void changed();

    //
    // only boring stuff below...
    //

private Q_SLOTS:
    void slotAvailableSelectionChanged(QTreeWidgetItem *);
    void slotCurrentOrderSelectionChanged(QTreeWidgetItem *);
    void slotDoubleUpButtonClicked();
    void slotUpButtonClicked();
    void slotDownButtonClicked();
    void slotDoubleDownButtonClicked();
    void slotLeftButtonClicked();
    void slotRightButtonClicked();

private:
    void takePlaceHolderItem();
    void enableDisableButtons(QTreeWidgetItem *);

private:
    class DNAttributeOrderConfigWidgetPrivate;
    std::unique_ptr<DNAttributeOrderConfigWidgetPrivate> const d;
protected:
    virtual void virtual_hook(int, void *);
};

}
