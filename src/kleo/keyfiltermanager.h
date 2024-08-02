/*
    keyfiltermanager.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <Libkleo/KeyFilter>

#include <QObject>
#include <QSortFilterProxyModel>

#include <gpgme++/global.h>

#include <memory>
#include <vector>

namespace GpgME
{
class Key;
class UserID;
}

class QModelIndex;
class QFont;
class QColor;
class QIcon;

namespace Kleo
{

class KLEO_EXPORT KeyFilterManager : public QObject
{
    Q_OBJECT
public:
    enum ModelRoles {
        FilterIdRole = Qt::UserRole,
        FilterMatchContextsRole,
        FilterRole,
    };

protected:
    explicit KeyFilterManager(QObject *parent = nullptr);
    ~KeyFilterManager() override;

public:
    static KeyFilterManager *instance();

    /**
     * Adds the rule that keys must match @p protocol to all filters.
     */
    void alwaysFilterByProtocol(GpgME::Protocol protocol);
    GpgME::Protocol protocol() const;

    const std::shared_ptr<KeyFilter> &filterMatching(const GpgME::Key &key, KeyFilter::MatchContexts contexts) const;
    std::vector<std::shared_ptr<KeyFilter>> filtersMatching(const GpgME::Key &key, KeyFilter::MatchContexts contexts) const;

    QAbstractItemModel *model() const;

    const std::shared_ptr<KeyFilter> &keyFilterByID(const QString &id) const;
    const std::shared_ptr<KeyFilter> &fromModelIndex(const QModelIndex &mi) const;
    QModelIndex toModelIndex(const std::shared_ptr<KeyFilter> &kf) const;

    void reload();

    QFont font(const GpgME::Key &key, const QFont &baseFont) const;
    QColor bgColor(const GpgME::Key &key) const;
    QColor bgColor(const GpgME::UserID &userID) const;
    QColor fgColor(const GpgME::Key &key) const;
    QColor fgColor(const GpgME::UserID &userID) const;
    QIcon icon(const GpgME::Key &key) const;

    class Private;

Q_SIGNALS:
    void alwaysFilterByProtocolChanged(GpgME::Protocol protocol);

private:
    std::unique_ptr<Private> d;
    static KeyFilterManager *mSelf;
};

class KLEO_EXPORT KeyFilterModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    KeyFilterModel(QObject *parent = nullptr);
    bool isCustomFilter(int row) const;
    void prependCustomFilter(const std::shared_ptr<KeyFilter> &filter);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;

    QModelIndex mapToSource(const QModelIndex &index) const override;
    QModelIndex mapFromSource(const QModelIndex &source_index) const override;

    QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const override;
    Qt::ItemFlags flags(const QModelIndex &index) const override;
    QModelIndex parent(const QModelIndex &) const override;
    QVariant data(const QModelIndex &index, int role) const override;

private:
    class Private;
    const std::unique_ptr<Private> d;
};
}
