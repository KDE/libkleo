/*
    keylistview.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <gpgme++/key.h>

#include <QByteArray>
#include <QTreeWidget>
#include <QHeaderView>
#include <QIcon>

class QFont;
class QColor;

namespace Kleo
{

// work around moc parser bug...
#define TEMPLATE_TYPENAME(T) template <typename T>
TEMPLATE_TYPENAME(T)
inline T *lvi_cast(QTreeWidgetItem *item)
{
    return item && (item->type() == T::RTTI)
           ? static_cast<T *>(item) : nullptr;
}

TEMPLATE_TYPENAME(T)
inline const T *lvi_cast(const QTreeWidgetItem *item)
{
    return item && (item->type() == T::RTTI)
           ? static_cast<const T *>(item) : nullptr;
}
#undef TEMPLATE_TYPENAME

class KeyListView;

class KeyListViewItem : public QTreeWidgetItem
{
public:
    KeyListViewItem(KeyListView *parent, const GpgME::Key &key);
    KeyListViewItem(KeyListView *parent, KeyListViewItem *after, const GpgME::Key &key);
    KeyListViewItem(KeyListViewItem *parent, const GpgME::Key &key);
    KeyListViewItem(KeyListViewItem *parent, KeyListViewItem *after, const GpgME::Key &key);
    ~KeyListViewItem() override;

    void setKey(const GpgME::Key &key);
    const GpgME::Key &key() const
    {
        return mKey;
    }

    enum { RTTI = QTreeWidgetItem::UserType + 1 };

    //
    // only boring stuff below:
    //
    virtual QString toolTip(int column) const;

    /*! \reimp for covariant return */
    KeyListView *listView() const;
    /*! \reimp for covariant return */
    KeyListViewItem *nextSibling() const;
    /*! \reimp */
    bool operator<(const QTreeWidgetItem &other) const override;
    /*! \reimp */
    void takeItem(QTreeWidgetItem *item);

private:
    GpgME::Key mKey;
};

class KLEO_EXPORT KeyListView : public QTreeWidget
{
    Q_OBJECT
    friend class KeyListViewItem;
public:

    class KLEO_EXPORT ColumnStrategy
    {
    public:
        virtual ~ColumnStrategy();
        virtual QString title(int column) const = 0;
        virtual int width(int column, const QFontMetrics &fm) const;
        virtual QHeaderView::ResizeMode resizeMode(int) const
        {
            return QHeaderView::Interactive;
        }

        virtual QString text(const GpgME::Key &key, int column) const = 0;
        virtual QString toolTip(const GpgME::Key &key, int column) const;
        virtual QIcon icon(const GpgME::Key &, int) const
        {
            return QIcon();
        }
        virtual int compare(const GpgME::Key &key1, const GpgME::Key &key2, const int column) const;
    };

    class KLEO_EXPORT DisplayStrategy
    {
    public:
        virtual ~DisplayStrategy();
        //font
        virtual QFont keyFont(const GpgME::Key &, const QFont &) const;
        //foreground
        virtual QColor keyForeground(const GpgME::Key &, const QColor &) const;
        //background
        virtual QColor keyBackground(const GpgME::Key &, const QColor &) const;
    };

    explicit KeyListView(const ColumnStrategy *strategy,
                         const DisplayStrategy *display = nullptr,
                         QWidget *parent = nullptr, Qt::WindowFlags f = {});

    ~KeyListView();

    const ColumnStrategy *columnStrategy() const
    {
        return mColumnStrategy;
    }
    const DisplayStrategy *displayStrategy() const
    {
        return mDisplayStrategy;
    }

    bool hierarchical() const
    {
        return mHierarchical;
    }
    virtual void setHierarchical(bool hier);

    void flushKeys()
    {
        slotUpdateTimeout();
    }

    bool isMultiSelection() const;

    KeyListViewItem *itemByFingerprint(const QByteArray &) const;

public:
    using QTreeWidget::selectionChanged; // for below, but moc doesn't like it to be in the Q_SIGNALS: section
Q_SIGNALS:
    void doubleClicked(Kleo::KeyListViewItem *, int);
    void returnPressed(Kleo::KeyListViewItem *);
    void selectionChanged(Kleo::KeyListViewItem *);
    void contextMenu(Kleo::KeyListViewItem *, const QPoint &);

protected:
    void keyPressEvent(QKeyEvent *event) override;

public Q_SLOTS:
    virtual void slotAddKey(const GpgME::Key &key);
    virtual void slotRefreshKey(const GpgME::Key &key);

    //
    // Only boring stuff below:
    //
private Q_SLOTS:
    void slotEmitDoubleClicked(QTreeWidgetItem *, int);
    void slotEmitReturnPressed(QTreeWidgetItem *);
    void slotEmitSelectionChanged();
    void slotEmitContextMenu(const QPoint &pos);
    void slotUpdateTimeout();

public:
    /*! \reimp for covariant return */
    KeyListViewItem *selectedItem() const;
    /*! \reimp */
    QList<KeyListViewItem *> selectedItems() const;
    /*! \reimp for covariant return */
    KeyListViewItem *firstChild() const;
    /*! \reimp */
    void clear();
    /*! \reimp */
    void takeItem(QTreeWidgetItem *);

private:
    void doHierarchicalInsert(const GpgME::Key &);
    void gatherScattered();
    void scatterGathered(KeyListViewItem *);
    void registerItem(KeyListViewItem *);
    void deregisterItem(const KeyListViewItem *);

private:
    const ColumnStrategy *mColumnStrategy = nullptr;
    const DisplayStrategy *mDisplayStrategy = nullptr;
    bool mHierarchical = false;

    class Private;
    Private *const d;
};
}

