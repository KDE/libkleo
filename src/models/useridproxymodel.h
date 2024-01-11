/*
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"
#include <Libkleo/KeyListSortFilterProxyModel>

namespace Kleo
{

class KLEO_EXPORT UserIDProxyModel : public Kleo::AbstractKeyListSortFilterProxyModel
{
    Q_OBJECT

public:
    explicit UserIDProxyModel(QObject *parent = nullptr);

    QModelIndex mapFromSource(const QModelIndex &sourceIndex) const override;
    QModelIndex mapToSource(const QModelIndex &proxyIndex) const override;
    int rowCount(const QModelIndex &parent = {}) const override;
    QModelIndex index(int row, int column, const QModelIndex &parent) const override;
    virtual QModelIndex parent(const QModelIndex &) const override;
    int columnCount(const QModelIndex &) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    int sourceRowForProxyIndex(const QModelIndex &index) const;
    int sourceOffsetForProxyIndex(const QModelIndex &index) const;
    int userIDsOfSourceRow(int sourceRow) const;
    UserIDProxyModel *clone() const override;
};
}
