/* -*- mode: c++; c-basic-offset:4 -*-
    models/subkeylistmodel.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QAbstractTableModel>

#include <kleo_export.h>

#include <vector>

namespace GpgME
{
class Key;
class Subkey;
}

namespace Kleo
{

class KLEO_EXPORT SubkeyListModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    explicit SubkeyListModel(QObject *parent = nullptr);
    ~SubkeyListModel() override;

    GpgME::Key key() const;

    enum Columns {
        ID,
        Type,
        ValidFrom,
        ValidUntil,
        Status,
        Strength,
        Usage,

        NumColumns,
        Icon = ID // which column shall the icon be displayed in?
    };

    GpgME::Subkey subkey(const QModelIndex &idx) const;
    std::vector<GpgME::Subkey> subkeys(const QList<QModelIndex> &indexes) const;

    using QAbstractTableModel::index;
    QModelIndex index(const GpgME::Subkey &subkey, int col = 0) const;
    QList<QModelIndex> indexes(const std::vector<GpgME::Subkey> &subkeys) const;

public Q_SLOTS:
    void setKey(const GpgME::Key &key);
    void clear();

public:
    int columnCount(const QModelIndex &pidx = QModelIndex()) const override;
    int rowCount(const QModelIndex &pidx = QModelIndex()) const override;
    QVariant headerData(int section, Qt::Orientation o, int role = Qt::DisplayRole) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

private:
    class Private;
    QScopedPointer<Private> const d;
};

}

