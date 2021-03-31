/* -*- mode: c++; c-basic-offset:4 -*-
    models/keylistmodelinterface.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

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
class KeyGroup;

class KLEO_EXPORT KeyListModelInterface
{
public:
    virtual ~KeyListModelInterface();

    virtual GpgME::Key key(const QModelIndex &idx) const = 0;
    virtual std::vector<GpgME::Key> keys(const QList<QModelIndex> &idxs) const = 0;

    virtual QModelIndex index(const GpgME::Key &key) const = 0;
    virtual QList<QModelIndex> indexes(const std::vector<GpgME::Key> &keys) const = 0;

    virtual KeyGroup group(const QModelIndex &idx) const = 0;
    virtual QModelIndex index(const KeyGroup &group) const = 0;
};

}

