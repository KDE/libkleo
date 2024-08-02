// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "kleo_export.h"

#include <gpgme++/key.h>

#include <QSortFilterProxyModel>

namespace Kleo
{

class KLEO_EXPORT UserIDListProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    UserIDListProxyModel(QObject *parent = nullptr);
    ~UserIDListProxyModel() override;

    bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override;
    void setShowOnlyOwnCertifications(bool showOnlyOwnCertifications);

    GpgME::UserID::Signature signature(const QModelIndex &index) const;
    GpgME::UserID userID(const QModelIndex &index) const;

private:
    class Private;
    std::unique_ptr<Private> d;
};

}
