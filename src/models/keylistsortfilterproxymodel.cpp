/* -*- mode: c++; c-basic-offset:4 -*-
    models/keylistsortfilterproxymodel.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "keylistsortfilterproxymodel.h"

#include "keylist.h"
#include "keylistmodel.h"
#include "kleo/keyfilter.h"
#include "kleo/keygroup.h"
#include "kleo/stl_util.h"

#include <libkleo_debug.h>

#include <gpgme++/key.h>

#include <gpgme++/gpgmepp_version.h>
#if GPGMEPP_VERSION >= 0x10E00 // 1.14.0
# define GPGME_HAS_REMARKS
#endif

using namespace Kleo;
using namespace GpgME;

AbstractKeyListSortFilterProxyModel::AbstractKeyListSortFilterProxyModel(QObject *p)
    : QSortFilterProxyModel(p), KeyListModelInterface()
{
    init();
}

AbstractKeyListSortFilterProxyModel::AbstractKeyListSortFilterProxyModel(const AbstractKeyListSortFilterProxyModel &other)
    : QSortFilterProxyModel(), KeyListModelInterface()
{
    Q_UNUSED(other)
    init();
}

void AbstractKeyListSortFilterProxyModel::init()
{
    setDynamicSortFilter(true);
    setSortRole(Qt::EditRole);    // EditRole can be expected to be in a less formatted way, better for sorting
    setFilterRole(Qt::DisplayRole);
    setFilterCaseSensitivity(Qt::CaseInsensitive);
}

AbstractKeyListSortFilterProxyModel::~AbstractKeyListSortFilterProxyModel() {}

Key AbstractKeyListSortFilterProxyModel::key(const QModelIndex &idx) const
{
    const KeyListModelInterface *const klmi = dynamic_cast<KeyListModelInterface *>(sourceModel());
    if (!klmi) {
        static Key null;
        return null;
    }
    return klmi->key(mapToSource(idx));
}

std::vector<Key> AbstractKeyListSortFilterProxyModel::keys(const QList<QModelIndex> &indexes) const
{
    const KeyListModelInterface *const klmi = dynamic_cast<KeyListModelInterface *>(sourceModel());
    if (!klmi) {
        return std::vector<Key>();
    }
    QList<QModelIndex> mapped;
    mapped.reserve(indexes.size());
    std::transform(indexes.begin(), indexes.end(),
                   std::back_inserter(mapped),
                   [this](const QModelIndex &idx) {
                       return mapToSource(idx);
                   });
    return klmi->keys(mapped);
}

KeyGroup AbstractKeyListSortFilterProxyModel::group(const QModelIndex &idx) const
{
    if (const KeyListModelInterface *const klmi = dynamic_cast<KeyListModelInterface *>(sourceModel())) {
        return klmi->group(mapToSource(idx));
    }
    return KeyGroup();
}

QModelIndex AbstractKeyListSortFilterProxyModel::index(const Key &key) const
{
    if (const KeyListModelInterface *const klmi = dynamic_cast<KeyListModelInterface *>(sourceModel())) {
        return mapFromSource(klmi->index(key));
    }
    return {};
}

QList<QModelIndex> AbstractKeyListSortFilterProxyModel::indexes(const std::vector<Key> &keys) const
{
    if (const KeyListModelInterface *const klmi = dynamic_cast<KeyListModelInterface *>(sourceModel())) {
        const QList<QModelIndex> source = klmi->indexes(keys);
        QList<QModelIndex> mapped;
        mapped.reserve(source.size());
        std::transform(source.begin(), source.end(),
                       std::back_inserter(mapped),
                       [this](const QModelIndex &idx) {
                           return mapFromSource(idx);
                       });
        return mapped;
    }
    return QList<QModelIndex>();
}

QModelIndex AbstractKeyListSortFilterProxyModel::index(const Kleo::KeyGroup& group) const
{
    if (const KeyListModelInterface *const klmi = dynamic_cast<KeyListModelInterface *>(sourceModel())) {
        return mapFromSource(klmi->index(group));
    }
    return {};
}

class KeyListSortFilterProxyModel::Private
{
    friend class ::Kleo::KeyListSortFilterProxyModel;
public:
    explicit Private()
        : keyFilter() {}
    ~Private() {}

private:
    std::shared_ptr<const KeyFilter> keyFilter;
};

KeyListSortFilterProxyModel::KeyListSortFilterProxyModel(QObject *p)
    : AbstractKeyListSortFilterProxyModel(p), d(new Private)
{

}

KeyListSortFilterProxyModel::KeyListSortFilterProxyModel(const KeyListSortFilterProxyModel &other)
    : AbstractKeyListSortFilterProxyModel(other), d(new Private(*other.d))
{

}

KeyListSortFilterProxyModel::~KeyListSortFilterProxyModel() {}

KeyListSortFilterProxyModel *KeyListSortFilterProxyModel::clone() const
{
    return new KeyListSortFilterProxyModel(*this);
}

std::shared_ptr<const KeyFilter> KeyListSortFilterProxyModel::keyFilter() const
{
    return d->keyFilter;
}

void KeyListSortFilterProxyModel::setKeyFilter(const std::shared_ptr<const KeyFilter> &kf)
{
    if (kf == d->keyFilter) {
        return;
    }
    d->keyFilter = kf;
    invalidate();
}

bool KeyListSortFilterProxyModel::filterAcceptsRow(int source_row, const QModelIndex &source_parent) const
{
    //
    // 0. Keep parents of matching children:
    //
    const QModelIndex index = sourceModel()->index(source_row, 0, source_parent);
    for (int i = 0, end = sourceModel()->rowCount(index); i != end; ++i)
        if (filterAcceptsRow(i, index)) {
            return true;
        }

    //
    // 1. Check filterRegExp
    //
    const int role = filterRole();
    const int col = filterKeyColumn();
    const QRegExp rx = filterRegExp();
    const QModelIndex nameIndex = sourceModel()->index(source_row, KeyList::PrettyName, source_parent);

    const KeyListModelInterface *const klm = dynamic_cast<KeyListModelInterface *>(sourceModel());
    Q_ASSERT(klm);
    const Key key = klm->key(nameIndex);
    const KeyGroup group = klm->group(nameIndex);
    Q_ASSERT(!key.isNull() || !group.isNull());

    if (col) {
        const QModelIndex colIdx = sourceModel()->index(source_row, col, source_parent);
        const QString content = colIdx.data(role).toString();
        if (!content.contains(rx)) {
            return false;
        }
    } else if (!key.isNull()) {
        // By default match against the full uid data (name / email / comment / dn)
        bool match = false;
        for (const auto &uid: key.userIDs()) {
            const auto id = QString::fromUtf8(uid.id());
            if (id.contains(rx)) {
                match = true;
                break;
            }
#ifdef GPGME_HAS_REMARKS
            // Also match against remarks (search tags)
            const auto alm = dynamic_cast<AbstractKeyListModel *>(sourceModel());
            if (alm) {
                const auto remarks = alm->data(alm->index(key, KeyList::Remarks));
                if (!remarks.isNull() && remarks.toString().contains(rx)) {
                    match = true;
                    break;
                }
            }
#endif
        }
        if (!match) {
            return false;
        }
    } else if (!group.isNull()) {
        if (!group.name().contains(rx)) {
            return false;
        }
    } else {
        return false;
    }

    //
    // 2. For keys check that key filters match (if any are defined)
    //
    if (d->keyFilter && !key.isNull()) {   // avoid artifacts when no filters are defined
        return d->keyFilter->matches(key, KeyFilter::Filtering);
    }

    // 3. match by default:
    return true;
}

