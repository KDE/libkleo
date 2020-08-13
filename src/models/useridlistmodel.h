/* -*- mode: c++; c-basic-offset:4 -*-
    models/userIDlistmodel.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2016 Andre Heinecke <aheinecke@gnupg.org>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifndef __KLEOPATRA_MODELS_USERIDLISTMODEL_H__
#define __KLEOPATRA_MODELS_USERIDLISTMODEL_H__

#include <QAbstractItemModel>

#include <kleo_export.h>

#include <gpgme++/key.h> // since Signature is nested in UserID...

class UIDModelItem;

namespace Kleo
{

class KLEO_EXPORT UserIDListModel : public QAbstractItemModel
{
    Q_OBJECT
public:
    explicit UserIDListModel(QObject *parent = nullptr);
    ~UserIDListModel() override;

    GpgME::Key key() const;

public:
    QVector<GpgME::UserID> userIDs(const QModelIndexList &indexs) const;
    QVector<GpgME::UserID::Signature> signatures(const QModelIndexList &indexs) const;
    void enableRemarks(bool value);

public Q_SLOTS:
    void setKey(const GpgME::Key &key);

public:
    int columnCount(const QModelIndex &pindex = QModelIndex()) const override;
    int rowCount(const QModelIndex &pindex = QModelIndex()) const override;
    QVariant headerData(int section, Qt::Orientation o, int role = Qt::DisplayRole) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    QModelIndex index(int row, int col, const QModelIndex &parent = QModelIndex()) const override;
    QModelIndex parent(const QModelIndex &index) const override;

private:
    GpgME::Key mKey;
    bool mRemarksEnabled = false;
    UIDModelItem *mRootItem = nullptr;
};

}

#endif /* __KLEOPATRA_MODELS_USERIDLISTMODEL_H__ */
