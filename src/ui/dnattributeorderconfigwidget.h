/*  -*- c++ -*-
    dnattributeorderconfigwidget.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QWidget>

namespace Kleo
{
class DNAttributeMapper;
}

class QTreeWidgetItem;

namespace Kleo
{

class KLEO_EXPORT DNAttributeOrderConfigWidget : public QWidget
{
    Q_OBJECT
public:
    /*! Use Kleo::DNAttributeMapper::instance()->configWidget( parent, name ) instead. */
    explicit DNAttributeOrderConfigWidget(DNAttributeMapper *mapper, QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~DNAttributeOrderConfigWidget();

    void load();
    void save() const;
    void defaults();

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
    class Private;
    Private *const d;
protected:
    virtual void virtual_hook(int, void *);
};

}

