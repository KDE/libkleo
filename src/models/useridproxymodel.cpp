/*
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "useridproxymodel.h"

#include "keylist.h"
#include "keylistmodel.h"
#include "kleo/keyfiltermanager.h"
#include "utils/algorithm.h"
#include "utils/formatting.h"
#include "utils/systeminfo.h"

#include <global.h>

#include <QColor>

#include <variant>

using namespace Kleo;

class UserIDProxyModel::Private
{
public:
    Private(UserIDProxyModel *qq);
    void loadUserIDs();
    QList<std::variant<GpgME::UserID, KeyGroup>> mIds;
    QAbstractItemModel *oldSourceModel = nullptr;
    UserIDProxyModel *q;
};

void UserIDProxyModel::Private::loadUserIDs()
{
    q->beginResetModel();
    mIds.clear();
    mIds.reserve(q->sourceModel()->rowCount());
    for (auto i = 0; i < q->sourceModel()->rowCount(); ++i) {
        const auto key = q->sourceModel()->index(i, 0).data(KeyList::KeyRole).value<GpgME::Key>();
        QList<GpgME::UserID> ids;
        if (key.isNull()) {
            mIds += q->sourceModel()->index(i, 0).data(KeyList::GroupRole).value<KeyGroup>();
        } else if (key.protocol() == GpgME::OpenPGP) {
            for (const auto &userID : key.userIDs()) {
                mIds += userID;
            }
        } else {
            QList<std::variant<GpgME::UserID, KeyGroup>> ids;
            for (const auto &userID : key.userIDs()) {
                const auto exists = Kleo::contains_if(ids, [userID](const auto &other) {
                    return !qstrcmp(std::get<GpgME::UserID>(other).email(), userID.email());
                });
                if (!exists && userID.email() && *userID.email()) {
                    ids += userID;
                }
            }
            if (ids.count() > 0) {
                mIds.append(ids);
            } else {
                mIds.append(key.userID(0));
            }
        }
    }
    q->endResetModel();
}

UserIDProxyModel::Private::Private(UserIDProxyModel *qq)
    : q(qq)
{
    connect(q, &UserIDProxyModel::sourceModelChanged, q, [this]() {
        if (oldSourceModel) {
            disconnect(oldSourceModel, nullptr, q, nullptr);
        }
        connect(q->sourceModel(), &QAbstractItemModel::dataChanged, q, [this]() {
            loadUserIDs();
        });
        connect(q->sourceModel(), &QAbstractItemModel::rowsInserted, q, [this]() {
            loadUserIDs();
        });
        connect(q->sourceModel(), &QAbstractItemModel::modelReset, q, [this]() {
            loadUserIDs();
        });
        oldSourceModel = q->sourceModel();
        loadUserIDs();
    });
}

UserIDProxyModel::UserIDProxyModel(QObject *parent)
    : AbstractKeyListSortFilterProxyModel(parent)
    , d{new Private(this)}
{
}

UserIDProxyModel::~UserIDProxyModel() = default;

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
    const auto &sourceKey = sourceIndex.data(KeyList::KeyRole).value<GpgME::Key>();
    if (sourceKey.isNull()) {
        const auto &sourceKeyGroup = sourceIndex.data(KeyList::GroupRole).value<KeyGroup>();
        for (int i = 0; i < d->mIds.count(); ++i) {
            if (std::holds_alternative<KeyGroup>(d->mIds[i]) && std::get<KeyGroup>(d->mIds[i]).id() == sourceKeyGroup.id()) {
                return index(i, sourceIndex.column(), {});
            }
        }
    } else {
        const auto &fingerprint = sourceKey.primaryFingerprint();
        for (int i = 0; i < d->mIds.count(); ++i) {
            if (std::holds_alternative<GpgME::UserID>(d->mIds[i]) && !qstrcmp(fingerprint, std::get<GpgME::UserID>(d->mIds[i]).parent().primaryFingerprint())) {
                return index(i, sourceIndex.column(), {});
            }
        }
    }

    return {};
}

QModelIndex UserIDProxyModel::mapToSource(const QModelIndex &proxyIndex) const
{
    if (!proxyIndex.isValid()) {
        return {};
    }
    const auto &entry = d->mIds[proxyIndex.row()];

    if (std::holds_alternative<KeyGroup>(entry)) {
        const auto &id = std::get<KeyGroup>(entry).id();
        for (int i = 0; i < sourceModel()->rowCount(); ++i) {
            if (sourceModel()->index(i, 0).data(KeyList::GroupRole).value<KeyGroup>().id() == id) {
                return sourceModel()->index(i, proxyIndex.column());
            }
        }
    } else {
        const auto &fingerprint = std::get<GpgME::UserID>(entry).parent().primaryFingerprint();
        for (int i = 0; i < sourceModel()->rowCount(); ++i) {
            if (!qstrcmp(sourceModel()->index(i, 0).data(KeyList::KeyRole).value<GpgME::Key>().primaryFingerprint(), fingerprint)) {
                return sourceModel()->index(i, proxyIndex.column());
            }
        }
    }

    return {};
}

int UserIDProxyModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    return d->mIds.count();
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
    const auto &entry = d->mIds[index.row()];
    if (std::holds_alternative<KeyGroup>(entry)) {
        return AbstractKeyListSortFilterProxyModel::data(index, role);
    }
    const auto &userId = std::get<GpgME::UserID>(entry);
    const auto &key = userId.parent();
    if (role == KeyList::UserIDRole) {
        return QVariant::fromValue(userId);
    }
    if ((role == Qt::DisplayRole || role == Qt::EditRole || role == Qt::AccessibleTextRole)) {
        if (index.column() == KeyList::Columns::PrettyName) {
            if (key.protocol() == GpgME::OpenPGP) {
                return Formatting::prettyName(userId);
            } else {
                return Formatting::prettyName(key);
            }
        }
        if (index.column() == KeyList::Columns::PrettyEMail) {
            return Formatting::prettyEMail(userId);
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

#include "moc_useridproxymodel.cpp"
