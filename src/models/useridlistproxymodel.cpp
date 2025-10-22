// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include "useridlistproxymodel.h"

#include "keycache.h"
#include "useridlistmodel.h"

#include <QtVersionChecks>

#include <gpgme++/key.h>

using namespace Kleo;

class UserIDListProxyModel::Private
{
public:
    bool showOnlyOwnCertifications = false;
};

UserIDListProxyModel::UserIDListProxyModel(QObject *parent)
    : QSortFilterProxyModel(parent)
    , d(std::make_unique<Private>())
{
}

UserIDListProxyModel::~UserIDListProxyModel() = default;

bool UserIDListProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    if (!d->showOnlyOwnCertifications || !sourceParent.isValid()) {
        return true;
    }
    const auto id = sourceModel()->index(sourceRow, 0, sourceParent).data(UserIDListModel::SignerKeyIdRole).value<const char *>();
    const auto key = KeyCache::instance()->findByKeyIDOrFingerprint(id);
    return !key.isNull() && key.hasSecret();
}

void UserIDListProxyModel::setShowOnlyOwnCertifications(bool showOnlyOwnCertifications)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    beginFilterChange();
    d->showOnlyOwnCertifications = showOnlyOwnCertifications;
    endFilterChange(QSortFilterProxyModel::Direction::Rows);
#else
    d->showOnlyOwnCertifications = showOnlyOwnCertifications;
    invalidateFilter();
#endif
}

GpgME::UserID::Signature UserIDListProxyModel::signature(const QModelIndex &index) const
{
    return dynamic_cast<UserIDListModel *>(sourceModel())->signature(mapToSource(index));
}

GpgME::UserID UserIDListProxyModel::userID(const QModelIndex &index) const
{
    return dynamic_cast<UserIDListModel *>(sourceModel())->userID(mapToSource(index));
}

#include "moc_useridlistproxymodel.cpp"
