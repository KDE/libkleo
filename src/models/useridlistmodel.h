/* -*- mode: c++; c-basic-offset:4 -*-
    models/useridlistmodel.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2016 Andre Heinecke <aheinecke@gnupg.org>
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <kleo_export.h>

#include <QAbstractItemModel>

#include <gpgme++/key.h> // since Signature is nested in UserID...

#include <memory>

class UIDModelItem;

namespace Kleo
{

class KLEO_EXPORT UserIDListModel : public QAbstractItemModel
{
    Q_OBJECT
public:
    enum class Column {
        Id,
        Name,
        Email,
        ValidFrom,
        ValidUntil,
        Status,
        Exportable,
        Tags,
        TrustSignatureDomain,
    };

    explicit UserIDListModel(QObject *parent = nullptr);
    ~UserIDListModel() override;

    GpgME::Key key() const;

public:
    GpgME::UserID userID(const QModelIndex &index) const;
    QVector<GpgME::UserID> userIDs(const QModelIndexList &indexs) const;
    GpgME::UserID::Signature signature(const QModelIndex &index) const;
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
    std::unique_ptr<UIDModelItem> mRootItem;
};

}

