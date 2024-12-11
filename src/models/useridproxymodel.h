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
    ~UserIDProxyModel() override;

    QModelIndex mapFromSource(const QModelIndex &sourceIndex) const override;
    QModelIndex mapToSource(const QModelIndex &proxyIndex) const override;
    int rowCount(const QModelIndex &parent = {}) const override;
    QModelIndex index(int row, int column, const QModelIndex &parent) const override;
    QModelIndex parent(const QModelIndex &) const override;
    int columnCount(const QModelIndex &) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    UserIDProxyModel *clone() const override;
    QModelIndex index(const KeyGroup &) const override;
    QModelIndex index(const GpgME::Key &key) const override;
    void setSourceModel(QAbstractItemModel *sourceModel) override;

private:
    class Private;
    const std::unique_ptr<Private> d;
};
}
