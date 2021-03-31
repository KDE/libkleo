/*  models/keyrearangecolumnsproxymodel.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "keylistmodelinterface.h"

#include <kleo_export.h>

#include <KRearrangeColumnsProxyModel>

namespace Kleo
{
/** KRearrangeColumnsProxymodel that implements the KeyListModelInterface. */
class KLEO_EXPORT KeyRearrangeColumnsProxyModel: public KRearrangeColumnsProxyModel,
                                                 public KeyListModelInterface
{
public:
    explicit KeyRearrangeColumnsProxyModel(QObject *parent = nullptr);

    GpgME::Key key(const QModelIndex &idx) const override;
    std::vector<GpgME::Key> keys(const QList<QModelIndex> &idxs) const override;

    KeyGroup group(const QModelIndex &idx) const override;

    using KRearrangeColumnsProxyModel::index;

    QModelIndex index(const GpgME::Key &key) const override;
    QList<QModelIndex> indexes(const std::vector<GpgME::Key> &keys) const override;

    QModelIndex index(const KeyGroup &group) const override;

    void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;
private:
    KeyListModelInterface *klm() const;
};
} // namespace Kleo
