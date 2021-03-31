/* -*- mode: c++; c-basic-offset:4 -*-
    models/keylistsortfilterproxymodel.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QSortFilterProxyModel>

#include "keylistmodelinterface.h"

#include <kleo_export.h>

#include <memory>

namespace GpgME
{
class Key;
}

namespace Kleo
{

class KeyFilter;

class KLEO_EXPORT AbstractKeyListSortFilterProxyModel : public QSortFilterProxyModel
                                                      , public KeyListModelInterface
{
    Q_OBJECT
protected:
    AbstractKeyListSortFilterProxyModel(const AbstractKeyListSortFilterProxyModel &);
public:
    explicit AbstractKeyListSortFilterProxyModel(QObject *parent = nullptr);
    ~AbstractKeyListSortFilterProxyModel() override;

    virtual AbstractKeyListSortFilterProxyModel *clone() const = 0;

    GpgME::Key key(const QModelIndex &idx) const override;
    std::vector<GpgME::Key> keys(const QList<QModelIndex> &indexes) const override;

    KeyGroup group(const QModelIndex &idx) const override;

    using QAbstractItemModel::index;
    QModelIndex index(const GpgME::Key &key) const override;
    QList<QModelIndex> indexes(const std::vector<GpgME::Key> &keys) const override;

    QModelIndex index(const KeyGroup &group) const override;

private:
    void init();
};

class KLEO_EXPORT KeyListSortFilterProxyModel : public AbstractKeyListSortFilterProxyModel
{
    Q_OBJECT
protected:
    KeyListSortFilterProxyModel(const KeyListSortFilterProxyModel &);
public:
    explicit KeyListSortFilterProxyModel(QObject *parent = nullptr);
    ~KeyListSortFilterProxyModel() override;

    std::shared_ptr<const KeyFilter> keyFilter() const;
    void setKeyFilter(const std::shared_ptr<const KeyFilter> &kf);

    KeyListSortFilterProxyModel *clone() const override;

protected:
    bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const override;

private:
    class Private;
    QScopedPointer<Private> const d;
};

}

