/*  models/keyrearangecolumnsproxymodel.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "keyrearrangecolumnsproxymodel.h"

#include "kleo/keygroup.h"

#include <gpgme++/key.h>

using namespace Kleo;
using namespace GpgME;

KeyRearrangeColumnsProxyModel::KeyRearrangeColumnsProxyModel(QObject *parent) :
    KRearrangeColumnsProxyModel(parent),
    KeyListModelInterface()
{

}

KeyListModelInterface *KeyRearrangeColumnsProxyModel::klm() const
{
    auto *ret = dynamic_cast<KeyListModelInterface *>(sourceModel());
    Q_ASSERT(ret);
    return ret;
}

Key KeyRearrangeColumnsProxyModel::key(const QModelIndex &idx) const
{
    return klm()->key(mapToSource(idx));
}

std::vector<GpgME::Key> KeyRearrangeColumnsProxyModel::keys(const QList<QModelIndex> &idxs) const
{
    QList<QModelIndex> srcIdxs;
    srcIdxs.reserve(idxs.count());
    for (const QModelIndex &idx : idxs) {
        srcIdxs << mapToSource(idx);
    }
    return klm()->keys(srcIdxs);
}

KeyGroup KeyRearrangeColumnsProxyModel::group(const QModelIndex &idx) const
{
    return klm()->group(mapToSource(idx));
}

QModelIndex KeyRearrangeColumnsProxyModel::index(const GpgME::Key &key) const
{
    return mapFromSource(klm()->index(key));
}

QList<QModelIndex> KeyRearrangeColumnsProxyModel::indexes(const std::vector<GpgME::Key> &keys) const
{
    QList<QModelIndex> myIdxs;
    const QList <QModelIndex> srcIdxs = klm()->indexes(keys);
    myIdxs.reserve(srcIdxs.count());
    for (const QModelIndex &idx : srcIdxs) {
        myIdxs << mapFromSource(idx);
    }
    return myIdxs;
}

QModelIndex KeyRearrangeColumnsProxyModel::index(const KeyGroup &group) const
{
    return mapFromSource(klm()->index(group));
}

void KeyRearrangeColumnsProxyModel::sort(int column, Qt::SortOrder order)
{
    const auto fakeIdx = createIndex(0, column);
    if (!fakeIdx.isValid()) {
        // Empty model?
        KRearrangeColumnsProxyModel::sort(column, order);
        return;
    }
    const auto remappedIdx = mapToSource(fakeIdx);
    KRearrangeColumnsProxyModel::sort(remappedIdx.column(), order);
}
