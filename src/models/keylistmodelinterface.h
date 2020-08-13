/* -*- mode: c++; c-basic-offset:4 -*-
    models/keylistmodelinterface.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifndef __KLEOPATRA_MODELS_KEYLISTMODELINTERFACE_H__
#define __KLEOPATRA_MODELS_KEYLISTMODELINTERFACE_H__

#include <vector>

namespace GpgME
{
class Key;
}

class QModelIndex;
template <typename T> class QList;

namespace Kleo
{

class KeyListModelInterface
{
public:
    virtual ~KeyListModelInterface() {}

    static const int FingerprintRole = 0xF1;
    static const int KeyRole = 0xF2;

    enum Columns {
        PrettyName,
        PrettyEMail,
        ValidFrom,
        ValidUntil,
        TechnicalDetails,
        ShortKeyID,
        KeyID,
        Fingerprint,
        Issuer,
        SerialNumber,
        OwnerTrust,
        Origin,
        LastUpdate,
#if 0
        LongKeyID,
#endif

        Validity,
        Summary, // Short summary line
        Remarks, // Additional remark notations
        NumColumns,
        Icon = PrettyName // which column shall the icon be displayed in?
    };

    virtual GpgME::Key key(const QModelIndex &idx) const = 0;
    virtual std::vector<GpgME::Key> keys(const QList<QModelIndex> &idxs) const = 0;

    virtual QModelIndex index(const GpgME::Key &key) const = 0;
    virtual QList<QModelIndex> indexes(const std::vector<GpgME::Key> &keys) const = 0;
};

}

#endif /* __KLEOPATRA_MODELS_KEYLISTMODELINTERFACE_H__ */
