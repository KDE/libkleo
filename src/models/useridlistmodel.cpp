/* -*- mode: c++; c-basic-offset:4 -*-
    models/useridlistmodel.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2016 Andre Heinecke <aheinecke@gnupg.org>
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "useridlistmodel.h"

#include "keycache.h"

#include <libkleo/formatting.h>

#include <KLocalizedString>

#include <QDate>
#include <QIcon>
#include <QVariant>

#include <gpgme++/key.h>

using namespace GpgME;
using namespace Kleo;

class UIDModelItem
{
    // A uid model item can either be a UserID::Signature or a UserID.
    // you can find out which it is if the uid or the signature return
    // null values. (Not null but isNull)
    //
public:
    explicit UIDModelItem(const UserID::Signature &sig, UIDModelItem *parentItem, bool showRemarks)
        : mParentItem{parentItem}
        , mSig{sig}
    {
        const auto name = Formatting::prettyName(sig);
        const auto email = Formatting::prettyEMail(sig);
        mItemData = {
            Formatting::prettyID(sig.signerKeyID()),
            name,
            email,
            Formatting::creationDateString(sig),
            Formatting::expirationDateString(sig),
            Formatting::validityShort(sig),
            sig.isExportable() ? QStringLiteral("✓") : QString{},
        };

        QString lastNotation;
        if (showRemarks && parentItem) {
            for (const auto &notation : sig.notations()) {
                if (notation.name() && !strcmp(notation.name(), "rem@gnupg.org")) {
                    lastNotation = QString::fromUtf8(notation.value());
                }
            }
        }
        mItemData.push_back(lastNotation);

        const auto trustSignatureDomain = Formatting::trustSignatureDomain(sig);
        mItemData.push_back(trustSignatureDomain);
        mAccessibleText = {
            Formatting::accessibleHexID(sig.signerKeyID()),
            name.isEmpty() ? i18nc("text for screen readers for an empty name", "no name") : QVariant{},
            email.isEmpty() ? i18nc("text for screen readers for an empty email address", "no email") : QVariant{},
            Formatting::accessibleDate(Formatting::creationDate(sig)),
            Formatting::accessibleExpirationDate(sig),
            {}, // display text is always okay
            sig.isExportable() ? i18nc("yes, is exportable", "yes") : i18nc("no, is not exportable", "no"),
            lastNotation.isEmpty() ? i18nc("accessible text for empty list of tags", "none") : QVariant{},
            trustSignatureDomain.isEmpty() ? i18n("not applicable") : QVariant{},
        };
        Q_ASSERT(mAccessibleText.size() == mItemData.size());
    }

    explicit UIDModelItem(const UserID &uid, UIDModelItem *parentItem)
        : mParentItem{parentItem}
        , mUid{uid}
    {
        mItemData = {Formatting::prettyUserID(uid)};
        // for the empty cells of the user ID rows we announce "User ID"
        mAccessibleText = {
            {}, // use displayed user ID
            i18n("User ID"),
            i18n("User ID"),
            i18n("User ID"),
            i18n("User ID"),
            i18n("User ID"),
            i18n("User ID"),
            i18n("User ID"),
            i18n("User ID"),
        };
    }

    // The root item
    UIDModelItem()
    {
        mItemData = {
            i18n("User ID / Certification Key ID"),
            i18n("Name"),
            i18n("E-Mail"),
            i18n("Valid From"),
            i18n("Valid Until"),
            i18n("Status"),
            i18n("Exportable"),
            i18n("Tags"),
            i18n("Trust Signature For"),
        };
        // mAccessibleText is explicitly left empty
    }

    ~UIDModelItem()
    {
        qDeleteAll(mChildItems);
    }

    void appendChild(UIDModelItem *child)
    {
        mChildItems << child;
    }

    UIDModelItem *child(int row) const
    {
        return mChildItems.value(row);
    }

    const UIDModelItem *constChild(int row) const
    {
        return mChildItems.value(row);
    }

    int childCount() const
    {
        return mChildItems.count();
    }

    int columnCount() const
    {
        if (childCount()) {
            // We take the value from the first child
            // as we are likely a UID and our children
            // are UID Signatures.
            return constChild(0)->columnCount();
        }
        return mItemData.count();
    }

    QVariant data(int column) const
    {
        return mItemData.value(column);
    }

    QVariant accessibleText(int column) const
    {
        return mAccessibleText.value(column);
    }

    QVariant toolTip(int column) const
    {
        if (!mSig.isNull()) {
            if (column == static_cast<int>(UserIDListModel::Column::Status)) {
                return i18n("class %1", mSig.certClass());
            } else if (column == static_cast<int>(UserIDListModel::Column::TrustSignatureDomain)) {
                return Formatting::trustSignature(mSig);
            }
        }
        return mItemData.value(column);
    }

    QVariant icon(int column) const
    {
        if (!mSig.isNull() && column == static_cast<int>(UserIDListModel::Column::Status)) {
            return Formatting::validityIcon(mSig);
        }
        return {};
    }

    int row() const
    {
        if (mParentItem) {
            return mParentItem->mChildItems.indexOf(const_cast<UIDModelItem *>(this));
        }
        return 0;
    }

    UIDModelItem *parentItem() const
    {
        return mParentItem;
    }

    UserID::Signature signature() const
    {
        return mSig;
    }

    UserID uid() const
    {
        return mUid;
    }

private:
    QList<UIDModelItem *> mChildItems;
    QList<QVariant> mItemData;
    QList<QVariant> mAccessibleText;
    UIDModelItem *mParentItem = nullptr;
    UserID::Signature mSig;
    UserID mUid;
};

UserIDListModel::UserIDListModel(QObject *p)
    : QAbstractItemModel{p}
{
}

UserIDListModel::~UserIDListModel() = default;

Key UserIDListModel::key() const
{
    return mKey;
}

void UserIDListModel::setKey(const Key &key)
{
    beginResetModel();
    mKey = key;

    mRootItem.reset(new UIDModelItem);
    for (int i = 0, ids = key.numUserIDs(); i < ids; ++i) {
        UserID uid = key.userID(i);
        auto uidItem = new UIDModelItem(uid, mRootItem.get());
        mRootItem->appendChild(uidItem);
        std::vector<UserID::Signature> sigs = uid.signatures();
        std::sort(sigs.begin(), sigs.end());
        for (const auto &sig : sigs) {
            auto sigItem = new UIDModelItem(sig, uidItem, mRemarksEnabled);
            uidItem->appendChild(sigItem);
        }
    }

    endResetModel();
}

int UserIDListModel::columnCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return static_cast<UIDModelItem *>(parent.internalPointer())->columnCount();
    }

    if (!mRootItem) {
        return 0;
    }

    return mRootItem->columnCount();
}

int UserIDListModel::rowCount(const QModelIndex &parent) const
{
    if (parent.column() > 0 || !mRootItem) {
        return 0;
    }

    const UIDModelItem *const parentItem = !parent.isValid() ? mRootItem.get() : static_cast<UIDModelItem *>(parent.internalPointer());
    return parentItem->childCount();
}

QModelIndex UserIDListModel::index(int row, int column, const QModelIndex &parent) const
{
    if (!hasIndex(row, column, parent)) {
        return {};
    }

    const UIDModelItem *const parentItem = !parent.isValid() ? mRootItem.get() : static_cast<UIDModelItem *>(parent.internalPointer());
    UIDModelItem *const childItem = parentItem->child(row);
    if (childItem) {
        return createIndex(row, column, childItem);
    } else {
        return QModelIndex();
    }
}

QModelIndex UserIDListModel::parent(const QModelIndex &index) const
{
    if (!index.isValid()) {
        return {};
    }
    auto childItem = static_cast<UIDModelItem *>(index.internalPointer());
    UIDModelItem *parentItem = childItem->parentItem();

    if (parentItem == mRootItem.get()) {
        return QModelIndex();
    }

    return createIndex(parentItem->row(), 0, parentItem);
}

QVariant UserIDListModel::headerData(int section, Qt::Orientation o, int role) const
{
    if (o == Qt::Horizontal && mRootItem) {
        if (role == Qt::DisplayRole || role == Qt::EditRole || role == Qt::ToolTipRole) {
            return mRootItem->data(section);
        } else if (role == Qt::AccessibleTextRole) {
            return mRootItem->accessibleText(section);
        }
    }
    return QVariant();
}

QVariant UserIDListModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid()) {
        return QVariant();
    }

    auto item = static_cast<UIDModelItem *>(index.internalPointer());

    switch (role) {
    case Qt::DisplayRole:
    case Qt::EditRole:
        return item->data(index.column());
    case Qt::AccessibleTextRole:
        return item->accessibleText(index.column());
    case Qt::ToolTipRole:
        return item->toolTip(index.column());
    case Qt::DecorationRole:
        return item->icon(index.column());
    default:;
    }

    return {};
}

UserID UserIDListModel::userID(const QModelIndex &index) const
{
    if (!index.isValid()) {
        return UserID();
    }
    UIDModelItem *item = static_cast<UIDModelItem *>(index.internalPointer());
    return item->uid();
}

QList<UserID> UserIDListModel::userIDs(const QModelIndexList &indexes) const
{
    QList<GpgME::UserID> ret;
    for (const QModelIndex &idx : indexes) {
        if (!idx.isValid()) {
            continue;
        }
        auto item = static_cast<UIDModelItem *>(idx.internalPointer());
        if (!item->uid().isNull()) {
            ret << item->uid();
        }
    }
    return ret;
}

UserID::Signature UserIDListModel::signature(const QModelIndex &index) const
{
    if (!index.isValid()) {
        return UserID::Signature();
    }
    UIDModelItem *item = static_cast<UIDModelItem *>(index.internalPointer());
    return item->signature();
}

QList<UserID::Signature> UserIDListModel::signatures(const QModelIndexList &indexes) const
{
    QList<GpgME::UserID::Signature> ret;
    for (const QModelIndex &idx : indexes) {
        if (!idx.isValid()) {
            continue;
        }
        auto item = static_cast<UIDModelItem *>(idx.internalPointer());
        if (!item->signature().isNull()) {
            ret << item->signature();
        }
    }
    return ret;
}

void UserIDListModel::enableRemarks(bool value)
{
    mRemarksEnabled = value;
}
