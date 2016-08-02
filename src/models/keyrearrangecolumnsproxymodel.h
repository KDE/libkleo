/*  models/keyrearangecolumnsproxymodel.h

    This file is part of Kleopatra, the KDE keymanager
    Copyright (c) 2016 Intevation GmbH

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
#ifndef KEYREARRANGECOLUMNSPROXYMODEL_H
#define KEYREARRANGECOLUMNSPROXYMODEL_H

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
    explicit KeyRearrangeColumnsProxyModel(QObject *parent = Q_NULLPTR);

    GpgME::Key key(const QModelIndex &idx) const Q_DECL_OVERRIDE;
    std::vector<GpgME::Key> keys(const QList<QModelIndex> &idxs) const Q_DECL_OVERRIDE;

    using KRearrangeColumnsProxyModel::index;

    QModelIndex index(const GpgME::Key &key) const Q_DECL_OVERRIDE;
    QList<QModelIndex> indexes(const std::vector<GpgME::Key> &keys) const Q_DECL_OVERRIDE;
private:
    KeyListModelInterface *klm() const;
};
} // namespace Kleo
#endif // KEYREARRANGECOLUMNSPROXYMODEL_H
