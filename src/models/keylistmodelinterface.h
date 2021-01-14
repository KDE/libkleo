/* -*- mode: c++; c-basic-offset:4 -*-
    models/keylistmodelinterface.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifndef __KLEOPATRA_MODELS_KEYLISTMODELINTERFACE_H__
#define __KLEOPATRA_MODELS_KEYLISTMODELINTERFACE_H__

#include <vector>

#include <kleo_export.h>

namespace GpgME
{
class Key;
}

class QModelIndex;
template <typename T> class QList;

namespace Kleo
{

class KLEO_EXPORT KeyListModelInterface
{
public:
    virtual ~KeyListModelInterface();

    virtual GpgME::Key key(const QModelIndex &idx) const = 0;
    virtual std::vector<GpgME::Key> keys(const QList<QModelIndex> &idxs) const = 0;

    virtual QModelIndex index(const GpgME::Key &key) const = 0;
    virtual QList<QModelIndex> indexes(const std::vector<GpgME::Key> &keys) const = 0;
};

}

#endif /* __KLEOPATRA_MODELS_KEYLISTMODELINTERFACE_H__ */
