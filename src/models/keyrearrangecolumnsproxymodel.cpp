/*  models/keyrearangecolumnsproxymodel.cpp

    This file is part of Kleopatra, the KDE keymanager
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH

    Kleopatra is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kleopatra is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    In addition, as a special exception, the copyright holders give
    permission to link the code of this program with any edition of
    the Qt library by Trolltech AS, Norway (or with modified versions
    of Qt that use the same license as Qt), and distribute linked
    combinations including the two.  You must obey the GNU General
    Public License in all respects for all of the code used other than
    Qt.  If you modify this file, you may extend this exception to
    your version of the file, but you are not obligated to do so.  If
    you do not wish to do so, delete this exception statement from
    your version.
*/
#include "keyrearrangecolumnsproxymodel.h"

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
    KeyListModelInterface *ret = dynamic_cast<KeyListModelInterface *>(sourceModel());
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
    for (const QModelIndex idx : idxs) {
        srcIdxs << mapToSource(idx);
    }
    return klm()->keys(srcIdxs);
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
    for (const QModelIndex idx : srcIdxs) {
        myIdxs << mapFromSource(idx);
    }
    return myIdxs;
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
