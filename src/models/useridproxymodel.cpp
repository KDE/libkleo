/*
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "useridproxymodel.h"

#include "keylist.h"
#include "keylistmodel.h"
#include "kleo/dn.h"
#include "kleo/keyfiltermanager.h"
#include "utils/formatting.h"
#include "utils/systeminfo.h"

#include <global.h>

#include <QColor>

using namespace Kleo;

Q_DECLARE_METATYPE(GpgME::UserID)

UserIDProxyModel::UserIDProxyModel(QObject *parent)
    : AbstractKeyListSortFilterProxyModel(parent)
{
}

static QVariant returnIfValid(const QColor &t)
{
    if (t.isValid()) {
        return t;
    } else {
        return QVariant();
    }
}

QModelIndex UserIDProxyModel::mapFromSource(const QModelIndex &sourceIndex) const
{
    if (!sourceIndex.isValid()) {
        return {};
    }
    int row = 0;
    for (int i = 0; i < sourceIndex.row(); i++) {
        row += userIDsOfSourceRow(i);
    }
    return index(row, sourceIndex.column(), {});
}

QModelIndex UserIDProxyModel::mapToSource(const QModelIndex &proxyIndex) const
{
    if (!proxyIndex.isValid()) {
        return {};
    }
    return sourceModel()->index(sourceRowForProxyIndex(proxyIndex), proxyIndex.column(), {});
}

int UserIDProxyModel::rowCount(const QModelIndex &parent) const
{
    if (!sourceModel()) {
        return 0;
    }
    if (parent.isValid()) {
        return 0;
    }
    int sum = 0;
    for (int i = 0; i < sourceModel()->rowCount(); i++) {
        sum += userIDsOfSourceRow(i);
    }
    return sum;
}

QModelIndex UserIDProxyModel::index(int row, int column, const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return {};
    }
    return createIndex(row, column, nullptr);
}

QModelIndex UserIDProxyModel::parent(const QModelIndex &) const
{
    return {};
}

int UserIDProxyModel::columnCount(const QModelIndex &index) const
{
    if (!sourceModel()) {
        return 0;
    }
    return sourceModel()->columnCount(mapToSource(index));
}

QVariant UserIDProxyModel::data(const QModelIndex &index, int role) const
{
    const auto row = sourceRowForProxyIndex(index);
    const auto offset = sourceOffsetForProxyIndex(index);
    const auto model = dynamic_cast<AbstractKeyListModel *>(sourceModel());
    const auto key = model->key(model->index(row, 0));
    if (key.isNull()) {
        return AbstractKeyListSortFilterProxyModel::data(index, role);
    }
    const auto userId = key.userID(offset);
    if (role == KeyList::UserIDRole) {
        return QVariant::fromValue(userId);
    }
    if ((role == Qt::DisplayRole || role == Qt::EditRole || role == Qt::AccessibleTextRole)) {
        if (index.column() == KeyList::Columns::PrettyName) {
            auto name = QString::fromUtf8(userId.name());
            if (name.isEmpty()) {
                return AbstractKeyListSortFilterProxyModel::data(index, role);
            }
            return name;
        }
        if (index.column() == KeyList::Columns::PrettyEMail) {
            return QString::fromUtf8(userId.email());
        }
        if (index.column() == KeyList::Columns::Validity) {
            return Formatting::complianceStringShort(userId);
        }
        if (index.column() == KeyList::Columns::Summary) {
            return Formatting::summaryLine(userId);
        }
        if (index.column() == KeyList::Columns::Origin) {
            return Formatting::origin(userId.origin());
        }
        if (index.column() == KeyList::Columns::LastUpdate) {
            if (role == Qt::AccessibleTextRole) {
                return Formatting::accessibleDate(userId.lastUpdate());
            } else {
                return Formatting::dateString(userId.lastUpdate());
            }
        }
    }
    if (role == Qt::BackgroundRole) {
        if (!SystemInfo::isHighContrastModeActive()) {
            return returnIfValid(KeyFilterManager::instance()->bgColor(userId));
        }
    } else if (role == Qt::ForegroundRole) {
        if (!SystemInfo::isHighContrastModeActive()) {
            return returnIfValid(KeyFilterManager::instance()->fgColor(userId));
        }
    }
    return AbstractKeyListSortFilterProxyModel::data(index, role);
}

int UserIDProxyModel::sourceRowForProxyIndex(const QModelIndex &index) const
{
    int row = index.row();
    int i;
    for (i = 0; row >= userIDsOfSourceRow(i); i++) {
        row -= userIDsOfSourceRow(i);
    }
    return i;
}

int UserIDProxyModel::sourceOffsetForProxyIndex(const QModelIndex &index) const
{
    int row = index.row();
    int i;
    for (i = 0; row >= userIDsOfSourceRow(i); i++) {
        row -= userIDsOfSourceRow(i);
    }
    auto model = dynamic_cast<AbstractKeyListModel *>(sourceModel());
    auto key = model->key(model->index(sourceRowForProxyIndex(index), 0));
    int tmp = row;
    for (int j = 0; j <= tmp; j++) {
        // account for filtered out S/MIME user IDs
        if (key.protocol() == GpgME::Protocol::CMS && !key.userID(j).email()) {
            row++;
        }
    }
    return row;
}

int UserIDProxyModel::userIDsOfSourceRow(int sourceRow) const
{
    auto model = dynamic_cast<AbstractKeyListModel *>(sourceModel());
    auto key = model->key(model->index(sourceRow, 0));

    if (key.isNull()) {
        // This is a keygroup; let's show it as one user id
        return 1;
    }
    if (key.protocol() == GpgME::OpenPGP) {
        return key.numUserIDs();
    }
    // Try to filter out some useless SMIME user ids
    int count = 0;
    const auto &uids = key.userIDs();
    for (auto it = uids.begin(); it != uids.end(); ++it) {
        const auto &uid = *it;
        if (uid.email()) {
            count++;
        }
    }
    return count;
}

UserIDProxyModel *UserIDProxyModel::clone() const
{
    auto model = new UserIDProxyModel(QObject::parent());
    model->setSourceModel(sourceModel());
    return model;
}

QModelIndex UserIDProxyModel::index(const KeyGroup &group) const
{
    Q_UNUSED(group);
    return {};
}

QModelIndex UserIDProxyModel::index(const GpgME::Key &key) const
{
    Q_UNUSED(key);
    return {};
}
