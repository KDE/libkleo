/* -*- mode: c++; c-basic-offset:4 -*-
    models/keylistmodel.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "keylistmodel.h"

#include "keycache.h"
#include "kleo/keygroup.h"
#include "kleo/predicates.h"
#include "kleo/keyfiltermanager.h"
#include "kleo/keyfilter.h"
#include "utils/algorithm.h"
#include "utils/formatting.h"

#ifdef KLEO_MODEL_TEST
# include <QAbstractItemModelTester>
#endif

#include <Libkleo/KeyFilterManager>
#include <Libkleo/KeyFilter>

#include <KLocalizedString>

#include <QFont>
#include <QColor>
#include <QHash>
#include <QIcon>
#include <QDate>
#include <gpgme++/key.h>

#ifndef Q_MOC_RUN // QTBUG-22829
#include <boost/graph/topological_sort.hpp>
#include <boost/graph/adjacency_list.hpp>
#endif

#include <algorithm>
#include <map>
#include <set>
#include <iterator>

#include <gpgme++/gpgmepp_version.h>
#if GPGMEPP_VERSION >= 0x10E00 // 1.14.0
# define GPGME_HAS_REMARKS
#endif

using namespace GpgME;
using namespace Kleo;
using namespace Kleo::KeyList;

Q_DECLARE_METATYPE(GpgME::Key)
Q_DECLARE_METATYPE(KeyGroup)

class AbstractKeyListModel::Private
{
    AbstractKeyListModel *const q;
public:
    explicit Private(AbstractKeyListModel *qq);

    void updateFromKeyCache();

public:
    int m_toolTipOptions = Formatting::Validity;
    mutable QHash<const char *, QVariant> prettyEMailCache;
    mutable QHash<const char *, QVariant> remarksCache;
    bool m_useKeyCache = false;
    bool m_modelResetInProgress = false;
    KeyList::Options m_keyListOptions = AllKeys;
    std::vector<GpgME::Key> m_remarkKeys;
};

AbstractKeyListModel::Private::Private(Kleo::AbstractKeyListModel *qq)
    : q(qq)
{
}

void AbstractKeyListModel::Private::updateFromKeyCache()
{
    if (m_useKeyCache) {
        q->setKeys(m_keyListOptions == SecretKeysOnly ? KeyCache::instance()->secretKeys() : KeyCache::instance()->keys());
        if (m_keyListOptions == IncludeGroups) {
            q->setGroups(KeyCache::instance()->groups());
        }
    }
}

AbstractKeyListModel::AbstractKeyListModel(QObject *p)
    : QAbstractItemModel(p), KeyListModelInterface(), d(new Private(this))
{
    connect(this, &QAbstractItemModel::modelAboutToBeReset, this, [this] () { d->m_modelResetInProgress = true; });
    connect(this, &QAbstractItemModel::modelReset, this, [this] () { d->m_modelResetInProgress = false; });
}

AbstractKeyListModel::~AbstractKeyListModel() {}

void AbstractKeyListModel::setToolTipOptions(int opts)
{
    d->m_toolTipOptions = opts;
}

int AbstractKeyListModel::toolTipOptions() const
{
    return d->m_toolTipOptions;
}

void AbstractKeyListModel::setRemarkKeys(const std::vector<GpgME::Key> &keys)
{
    d->m_remarkKeys = keys;
}

std::vector<GpgME::Key> AbstractKeyListModel::remarkKeys() const
{
    return d->m_remarkKeys;
}

Key AbstractKeyListModel::key(const QModelIndex &idx) const
{
    if (idx.isValid()) {
        return doMapToKey(idx);
    } else {
        return Key::null;
    }
}

std::vector<Key> AbstractKeyListModel::keys(const QList<QModelIndex> &indexes) const
{
    std::vector<Key> result;
    result.reserve(indexes.size());
    std::transform(indexes.begin(), indexes.end(),
                   std::back_inserter(result),
                   [this](const QModelIndex &idx) {
                       return this->key(idx);
                   });
    result.erase(std::remove_if(result.begin(), result.end(), std::mem_fn(&GpgME::Key::isNull)), result.end());
    _detail::remove_duplicates_by_fpr(result);
    return result;
}

KeyGroup AbstractKeyListModel::group(const QModelIndex &idx) const
{
    if (idx.isValid()) {
        return doMapToGroup(idx);
    } else {
        return KeyGroup();
    }
}

QModelIndex AbstractKeyListModel::index(const Key &key) const
{
    return index(key, 0);
}

QModelIndex AbstractKeyListModel::index(const Key &key, int col) const
{
    if (key.isNull() || col < 0 || col >= NumColumns) {
        return {};
    } else {
        return doMapFromKey(key, col);
    }
}

QList<QModelIndex> AbstractKeyListModel::indexes(const std::vector<Key> &keys) const
{
    QList<QModelIndex> result;
    result.reserve(keys.size());
    std::transform(keys.begin(), keys.end(),
                   std::back_inserter(result),
                   [this](const Key &key) {
                       return this->index(key);
                   });
    return result;
}

QModelIndex AbstractKeyListModel::index(const KeyGroup &group) const
{
    return index(group, 0);
}

QModelIndex AbstractKeyListModel::index(const KeyGroup &group, int col) const
{
    if (group.isNull() || col < 0 || col >= NumColumns) {
        return {};
    } else {
        return doMapFromGroup(group, col);
    }
}

void AbstractKeyListModel::setKeys(const std::vector<Key> &keys)
{
    beginResetModel();
    clear(Keys);
    addKeys(keys);
    endResetModel();
}

QModelIndex AbstractKeyListModel::addKey(const Key &key)
{
    const std::vector<Key> vec(1, key);
    const QList<QModelIndex> l = doAddKeys(vec);
    return l.empty() ? QModelIndex() : l.front();
}

void AbstractKeyListModel::removeKey(const Key &key)
{
    if (key.isNull()) {
        return;
    }
    doRemoveKey(key);
    d->prettyEMailCache.remove(key.primaryFingerprint());
    d->remarksCache.remove(key.primaryFingerprint());
}

QList<QModelIndex> AbstractKeyListModel::addKeys(const std::vector<Key> &keys)
{
    std::vector<Key> sorted;
    sorted.reserve(keys.size());
    std::remove_copy_if(keys.begin(), keys.end(),
                        std::back_inserter(sorted),
                        std::mem_fn(&Key::isNull));
    std::sort(sorted.begin(), sorted.end(), _detail::ByFingerprint<std::less>());
    return doAddKeys(sorted);
}

void AbstractKeyListModel::setGroups(const std::vector<KeyGroup> &groups)
{
    beginResetModel();
    clear(Groups);
    doSetGroups(groups);
    endResetModel();
}

QModelIndex AbstractKeyListModel::addGroup(const KeyGroup &group)
{
    if (group.isNull()) {
        return QModelIndex();
    }
    return doAddGroup(group);
}

bool AbstractKeyListModel::removeGroup(const KeyGroup &group)
{
    if (group.isNull()) {
        return false;
    }
    return doRemoveGroup(group);
}

void AbstractKeyListModel::clear(ItemTypes types)
{
    const bool inReset = modelResetInProgress();
    if (!inReset) {
        beginResetModel();
    }
    doClear(types);
    if (types & Keys) {
        d->prettyEMailCache.clear();
        d->remarksCache.clear();
    }
    if (!inReset) {
        endResetModel();
    }
}

int AbstractKeyListModel::columnCount(const QModelIndex &) const
{
    return NumColumns;
}

QVariant AbstractKeyListModel::headerData(int section, Qt::Orientation o, int role) const
{
    if (o == Qt::Horizontal)
        if (role == Qt::DisplayRole || role == Qt::EditRole || role == Qt::ToolTipRole)
            switch (section) {
            case PrettyName:       return i18n("Name");
            case PrettyEMail:      return i18n("E-Mail");
            case Validity:         return i18n("User-IDs");
            case ValidFrom:        return i18n("Valid From");
            case ValidUntil:       return i18n("Valid Until");
            case TechnicalDetails: return i18n("Protocol");
            case ShortKeyID:       return i18n("Key-ID");
            case KeyID:            return i18n("Key-ID");
            case Fingerprint:      return i18n("Fingerprint");
            case Issuer:           return i18n("Issuer");
            case SerialNumber:     return i18n("Serial Number");
            case Origin:           return i18n("Origin");
            case LastUpdate:       return i18n("Last Update");
            case OwnerTrust:       return i18n("Certification Trust");
            case Remarks:          return i18n("Tags");
            case NumColumns:;
            }
    return QVariant();
}

static QVariant returnIfValid(const QColor &t)
{
    if (t.isValid()) {
        return t;
    } else {
        return QVariant();
    }
}

static QVariant returnIfValid(const QIcon &t)
{
    if (!t.isNull()) {
        return t;
    } else {
        return QVariant();
    }
}

QVariant AbstractKeyListModel::data(const QModelIndex &index, int role) const
{
    const Key key = this->key(index);
    if (!key.isNull()) {
        return data(key, index.column(), role);
    }

    const KeyGroup group = this->group(index);
    if (!group.isNull()) {
        return data(group, index.column(), role);
    }

    return QVariant();
}

QVariant AbstractKeyListModel::data(const Key &key, int column, int role) const
{
   if (role == Qt::DisplayRole || role == Qt::EditRole) {
        switch (column) {
        case PrettyName:
            return Formatting::prettyName(key);
        case PrettyEMail:
            if (const char *const fpr = key.primaryFingerprint()) {
                const QHash<const char *, QVariant>::const_iterator it = d->prettyEMailCache.constFind(fpr);
                if (it != d->prettyEMailCache.constEnd()) {
                    return *it;
                } else {
                    return d->prettyEMailCache[fpr] = Formatting::prettyEMail(key);
                }
            } else {
                return QVariant();
            }
        case Validity:
            return Formatting::complianceStringShort(key);
        case ValidFrom:
            if (role == Qt::EditRole) {
                return Formatting::creationDate(key);
            } else {
                return Formatting::creationDateString(key);
            }
        case ValidUntil:
            if (role == Qt::EditRole) {
                return Formatting::expirationDate(key);
            } else {
                return Formatting::expirationDateString(key);
            }
        case TechnicalDetails:
            return Formatting::type(key);
        case ShortKeyID:
            return QString::fromLatin1(key.shortKeyID());
        case KeyID:
            return Formatting::prettyID(key.keyID());
        case Summary:
            return Formatting::summaryLine(key);
        case Fingerprint:
            return Formatting::prettyID(key.primaryFingerprint());
        case Issuer:
            return QString::fromUtf8(key.issuerName());
        case Origin:
            return Formatting::origin(key.origin());
        case LastUpdate:
            return Formatting::dateString(key.lastUpdate());
        case SerialNumber:
            return QString::fromUtf8(key.issuerSerial());
        case OwnerTrust:
            return Formatting::ownerTrustShort(key.ownerTrust());
        case Remarks:
#ifdef GPGME_HAS_REMARKS
            {
                const char *const fpr = key.primaryFingerprint();
                if (fpr && key.protocol() == GpgME::OpenPGP && key.numUserIDs() &&
                        d->m_remarkKeys.size()) {
                    if (!(key.keyListMode() & GpgME::SignatureNotations)) {
                        return i18n("Loading...");
                    }
                    const QHash<const char *, QVariant>::const_iterator it = d->remarksCache.constFind(fpr);
                    if (it != d->remarksCache.constEnd()) {
                        return *it;
                    } else {
                        GpgME::Error err;
                        const auto remarks = key.userID(0).remarks(d->m_remarkKeys, err);
                        if (remarks.size() == 1) {
                            const auto remark = QString::fromStdString(remarks[0]);
                            return d->remarksCache[fpr] = remark;
                        } else {
                            QStringList remarkList;
                            remarkList.reserve(remarks.size());
                            for (const auto &rem: remarks) {
                                remarkList << QString::fromStdString(rem);
                            }
                            const auto remark = remarkList.join(QStringLiteral("; "));
                            return d->remarksCache[fpr] = remark;
                        }
                    }
                } else {
                    return QVariant();
                }
            }
#endif
            return QVariant();
        case NumColumns:
            break;
        }
    } else if (role == Qt::ToolTipRole) {
        return Formatting::toolTip(key, toolTipOptions());
    } else if (role == Qt::FontRole) {
        return KeyFilterManager::instance()->font(key, (column == ShortKeyID || column == KeyID || column == Fingerprint) ? QFont(QStringLiteral("monospace")) : QFont());
    } else if (role == Qt::DecorationRole) {
        return column == Icon ? returnIfValid(KeyFilterManager::instance()->icon(key)) : QVariant();
    } else if (role == Qt::BackgroundRole) {
        return returnIfValid(KeyFilterManager::instance()->bgColor(key));
    } else if (role == Qt::ForegroundRole) {
        return returnIfValid(KeyFilterManager::instance()->fgColor(key));
    } else if (role == FingerprintRole) {
        return QString::fromLatin1(key.primaryFingerprint());
    } else if (role == KeyRole) {
        return QVariant::fromValue(key);
    }
    return QVariant();
}

QVariant AbstractKeyListModel::data(const KeyGroup &group, int column, int role) const
{
    if (role == Qt::DisplayRole || role == Qt::EditRole) {
        switch (column) {
        case PrettyName:
            return group.name();
        case PrettyEMail:
            return QVariant();
        case Validity:
            return Formatting::complianceStringShort(group);
        case ValidFrom:
            return QString();
        case ValidUntil:
            return QString();
        case TechnicalDetails:
            return Formatting::type(group);
        case ShortKeyID:
            return QString();
        case KeyID:
            return QString();
        case Summary:
            return Formatting::summaryLine(group);  // used for filtering
        case Fingerprint:
            return QString();
        case Issuer:
            return QString();
        case Origin:
            return QString();
        case LastUpdate:
            return QString();
        case SerialNumber:
            return QString();
        case OwnerTrust:
            return QString();
        case Remarks:
            return QVariant();
        case NumColumns:
            break;
        }
    } else if (role == Qt::ToolTipRole) {
        return Formatting::toolTip(group, toolTipOptions());
    } else if (role == Qt::FontRole) {
        return QFont();
    } else if (role == Qt::DecorationRole) {
        return column == Icon ? QIcon::fromTheme(QStringLiteral("group")) : QVariant();
    } else if (role == Qt::BackgroundRole) {
    } else if (role == Qt::ForegroundRole) {
    } else if (role == GroupRole) {
        return QVariant::fromValue(group);
    }
    return QVariant();
}

bool AbstractKeyListModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    Q_UNUSED(role)
    Q_ASSERT(value.canConvert<KeyGroup>());
    if (value.canConvert<KeyGroup>()) {
        const KeyGroup group = value.value<KeyGroup>();
        return doSetGroupData(index, group);
    }

    return false;
}

bool AbstractKeyListModel::modelResetInProgress()
{
    return d->m_modelResetInProgress;
}

namespace
{
template <typename Base>
class TableModelMixin : public Base
{
public:
    explicit TableModelMixin(QObject *p = nullptr) : Base(p) {}
    ~TableModelMixin() {}

    using Base::index;
    QModelIndex index(int row, int column, const QModelIndex &pidx = QModelIndex()) const override
    {
        return this->hasIndex(row, column, pidx) ? this->createIndex(row, column, nullptr) : QModelIndex();
    }

private:
    QModelIndex parent(const QModelIndex &) const override
    {
        return QModelIndex();
    }
    bool hasChildren(const QModelIndex &pidx) const override
    {
        return (pidx.model() == this || !pidx.isValid()) && this->rowCount(pidx) > 0 && this->columnCount(pidx) > 0;
    }
};

class FlatKeyListModel
#ifndef Q_MOC_RUN
    : public TableModelMixin<AbstractKeyListModel>
#else
    : public AbstractKeyListModel
#endif
{
    Q_OBJECT
public:
    explicit FlatKeyListModel(QObject *parent = nullptr);
    ~FlatKeyListModel() override;

    int rowCount(const QModelIndex &pidx) const override
    {
        return pidx.isValid() ? 0 : mKeysByFingerprint.size() + mGroups.size();
    }

private:
    Key doMapToKey(const QModelIndex &index) const override;
    QModelIndex doMapFromKey(const Key &key, int col) const override;
    QList<QModelIndex> doAddKeys(const std::vector<Key> &keys) override;
    void doRemoveKey(const Key &key) override;

    KeyGroup doMapToGroup(const QModelIndex &index) const override;
    QModelIndex doMapFromGroup(const KeyGroup &group, int column) const override;
    void doSetGroups(const std::vector<KeyGroup> &groups) override;
    QModelIndex doAddGroup(const KeyGroup &group) override;
    bool doSetGroupData(const QModelIndex &index, const KeyGroup &group) override;
    bool doRemoveGroup(const KeyGroup &group) override;

    void doClear(ItemTypes types) override
    {
        if (types & Keys) {
            mKeysByFingerprint.clear();
        }
        if (types & Groups) {
            mGroups.clear();
        }
    }

    int firstGroupRow() const
    {
        return mKeysByFingerprint.size();
    }

    int lastGroupRow() const
    {
        return mKeysByFingerprint.size() + mGroups.size() - 1;
    }

    int groupIndex(const QModelIndex &index) const
    {
        if (!index.isValid()
                || index.row() < firstGroupRow() || index.row() > lastGroupRow()
                || index.column() >= NumColumns) {
            return -1;
        }
        return index.row() - firstGroupRow();
    }

private:
    std::vector<Key> mKeysByFingerprint;
    std::vector<KeyGroup> mGroups;
};

class HierarchicalKeyListModel : public AbstractKeyListModel
{
    Q_OBJECT
public:
    explicit HierarchicalKeyListModel(QObject *parent = nullptr);
    ~HierarchicalKeyListModel() override;

    int rowCount(const QModelIndex &pidx) const override;
    using AbstractKeyListModel::index;
    QModelIndex index(int row, int col, const QModelIndex &pidx) const override;
    QModelIndex parent(const QModelIndex &idx) const override;

    bool hasChildren(const QModelIndex &pidx) const override
    {
        return rowCount(pidx) > 0;
    }

private:
    Key doMapToKey(const QModelIndex &index) const override;
    QModelIndex doMapFromKey(const Key &key, int col) const override;
    QList<QModelIndex> doAddKeys(const std::vector<Key> &keys) override;
    void doRemoveKey(const Key &key) override;

    KeyGroup doMapToGroup(const QModelIndex &index) const override;
    QModelIndex doMapFromGroup(const KeyGroup &group, int column) const override;
    void doSetGroups(const std::vector<KeyGroup> &groups) override;
    QModelIndex doAddGroup(const KeyGroup &group) override;
    bool doSetGroupData(const QModelIndex &index, const KeyGroup &group) override;
    bool doRemoveGroup(const KeyGroup &group) override;

    void doClear(ItemTypes types) override
    {
        if (types & Keys) {
            mTopLevels.clear();
            mKeysByFingerprint.clear();
            mKeysByExistingParent.clear();
            mKeysByNonExistingParent.clear();
        }
        if (types & Groups) {
            mGroups.clear();
        }
    }

    int firstGroupRow() const
    {
        return mTopLevels.size();
    }

    int lastGroupRow() const
    {
        return mTopLevels.size() + mGroups.size() - 1;
    }

    int groupIndex(const QModelIndex &index) const
    {
        if (!index.isValid()
                || index.row() < firstGroupRow() || index.row() > lastGroupRow()
                || index.column() >= NumColumns) {
            return -1;
        }
        return index.row() - firstGroupRow();
    }

private:
    void addTopLevelKey(const Key &key);
    void addKeyWithParent(const char *issuer_fpr, const Key &key);
    void addKeyWithoutParent(const char *issuer_fpr, const Key &key);

private:
    typedef std::map< std::string, std::vector<Key> > Map;
    std::vector<Key> mKeysByFingerprint; // all keys
    Map mKeysByExistingParent, mKeysByNonExistingParent; // parent->child map
    std::vector<Key> mTopLevels; // all roots + parent-less
    std::vector<KeyGroup> mGroups;
};

static const char *cleanChainID(const Key &key)
{
    if (key.isRoot()) {
        return "";
    }
    if (const char *chid = key.chainID()) {
        return chid;
    }
    return "";
}

}

FlatKeyListModel::FlatKeyListModel(QObject *p)
    : TableModelMixin<AbstractKeyListModel>(p)
{
}

FlatKeyListModel::~FlatKeyListModel() {}

Key FlatKeyListModel::doMapToKey(const QModelIndex &idx) const
{
    Q_ASSERT(idx.isValid());
    if (static_cast<unsigned>(idx.row()) < mKeysByFingerprint.size() && idx.column() < NumColumns) {
        return mKeysByFingerprint[ idx.row() ];
    } else {
        return Key::null;
    }
}

QModelIndex FlatKeyListModel::doMapFromKey(const Key &key, int col) const
{
    Q_ASSERT(!key.isNull());
    const std::vector<Key>::const_iterator it
        = std::lower_bound(mKeysByFingerprint.begin(), mKeysByFingerprint.end(),
                           key, _detail::ByFingerprint<std::less>());
    if (it == mKeysByFingerprint.end() || !_detail::ByFingerprint<std::equal_to>()(*it, key)) {
        return {};
    } else {
        return createIndex(it - mKeysByFingerprint.begin(), col);
    }
}

QList<QModelIndex> FlatKeyListModel::doAddKeys(const std::vector<Key> &keys)
{
    Q_ASSERT(std::is_sorted(keys.begin(), keys.end(), _detail::ByFingerprint<std::less>()));

    if (keys.empty()) {
        return QList<QModelIndex>();
    }

    for (auto it = keys.begin(), end = keys.end(); it != end; ++it) {

        // find an insertion point:
        const std::vector<Key>::iterator pos = std::upper_bound(mKeysByFingerprint.begin(), mKeysByFingerprint.end(), *it, _detail::ByFingerprint<std::less>());
        const unsigned int idx = std::distance(mKeysByFingerprint.begin(), pos);

        if (idx > 0 && qstrcmp(mKeysByFingerprint[idx - 1].primaryFingerprint(), it->primaryFingerprint()) == 0) {
            // key existed before - replace with new one:
            mKeysByFingerprint[idx - 1] = *it;
            if (!modelResetInProgress()) {
                Q_EMIT dataChanged(createIndex(idx - 1, 0), createIndex(idx - 1, NumColumns - 1));
            }
        } else {
            // new key - insert:
            if (!modelResetInProgress()) {
                beginInsertRows(QModelIndex(), idx, idx);
            }
            mKeysByFingerprint.insert(pos, *it);
            if (!modelResetInProgress()) {
                endInsertRows();
            }
        }
    }

    return indexes(keys);
}

void FlatKeyListModel::doRemoveKey(const Key &key)
{
    const std::vector<Key>::iterator it
        = Kleo::binary_find(mKeysByFingerprint.begin(), mKeysByFingerprint.end(),
                            key, _detail::ByFingerprint<std::less>());
    if (it == mKeysByFingerprint.end()) {
        return;
    }

    const unsigned int row = std::distance(mKeysByFingerprint.begin(), it);
    if (!modelResetInProgress()) {
        beginRemoveRows(QModelIndex(), row, row);
    }
    mKeysByFingerprint.erase(it);
    if (!modelResetInProgress()) {
        endRemoveRows();
    }
}

KeyGroup FlatKeyListModel::doMapToGroup(const QModelIndex &idx) const
{
    Q_ASSERT(idx.isValid());
    if (static_cast<unsigned>(idx.row()) >= mKeysByFingerprint.size()
            && static_cast<unsigned>(idx.row()) < mKeysByFingerprint.size() + mGroups.size()
            && idx.column() < NumColumns) {
        return mGroups[ idx.row() - mKeysByFingerprint.size() ];
    } else {
        return KeyGroup();
    }
}

QModelIndex FlatKeyListModel::doMapFromGroup(const KeyGroup &group, int column) const
{
    Q_ASSERT(!group.isNull());
    const auto it = std::find_if(mGroups.cbegin(), mGroups.cend(),
                                 [group](const KeyGroup &g) {
                                     return g.source() == group.source() && g.id() == group.id();
                                 });
    if (it == mGroups.cend()) {
        return QModelIndex();
    } else {
        return createIndex(it - mGroups.cbegin() + mKeysByFingerprint.size(), column);
    }
}

void FlatKeyListModel::doSetGroups(const std::vector<KeyGroup> &groups)
{
    Q_ASSERT(mGroups.empty());  // ensure that groups have been cleared
    const int first = mKeysByFingerprint.size();
    const int last = first + groups.size() - 1;
    if (!modelResetInProgress()) {
        beginInsertRows(QModelIndex(), first, last);
    }
    mGroups = groups;
    if (!modelResetInProgress()) {
        endInsertRows();
    }
}

QModelIndex FlatKeyListModel::doAddGroup(const KeyGroup &group)
{
    const int newRow = lastGroupRow() + 1;
    if (!modelResetInProgress()) {
        beginInsertRows(QModelIndex(), newRow, newRow);
    }
    mGroups.push_back(group);
    if (!modelResetInProgress()) {
        endInsertRows();
    }
    return createIndex(newRow, 0);
}

bool FlatKeyListModel::doSetGroupData(const QModelIndex &index, const KeyGroup &group)
{
    if (group.isNull()) {
        return false;
    }
    const int groupIndex = this->groupIndex(index);
    if (groupIndex == -1) {
        return false;
    }
    mGroups[groupIndex] = group;
    if (!modelResetInProgress()) {
        Q_EMIT dataChanged(createIndex(index.row(), 0), createIndex(index.row(), NumColumns - 1));
    }
    return true;
}

bool FlatKeyListModel::doRemoveGroup(const KeyGroup &group)
{
    const QModelIndex modelIndex = doMapFromGroup(group, 0);
    if (!modelIndex.isValid()) {
        return false;
    }
    const int groupIndex = this->groupIndex(modelIndex);
    Q_ASSERT(groupIndex != -1);
    if (groupIndex == -1) {
        return false;
    }
    if (!modelResetInProgress()) {
        beginRemoveRows(QModelIndex(), modelIndex.row(), modelIndex.row());
    }
    mGroups.erase(mGroups.begin() + groupIndex);
    if (!modelResetInProgress()) {
        endRemoveRows();
    }
    return true;
}

HierarchicalKeyListModel::HierarchicalKeyListModel(QObject *p)
    : AbstractKeyListModel(p),
      mKeysByFingerprint(),
      mKeysByExistingParent(),
      mKeysByNonExistingParent(),
      mTopLevels()
{

}

HierarchicalKeyListModel::~HierarchicalKeyListModel() {}

int HierarchicalKeyListModel::rowCount(const QModelIndex &pidx) const
{

    // toplevel item:
    if (!pidx.isValid()) {
        return mTopLevels.size() + mGroups.size();
    }

    if (pidx.column() != 0) {
        return 0;
    }

    // non-toplevel item - find the number of subjects for this issuer:
    const Key issuer = this->key(pidx);
    const char *const fpr = issuer.primaryFingerprint();
    if (!fpr || !*fpr) {
        return 0;
    }
    const Map::const_iterator it = mKeysByExistingParent.find(fpr);
    if (it == mKeysByExistingParent.end()) {
        return 0;
    }
    return it->second.size();
}

QModelIndex HierarchicalKeyListModel::index(int row, int col, const QModelIndex &pidx) const
{

    if (row < 0 || col < 0 || col >= NumColumns) {
        return {};
    }

    // toplevel item:
    if (!pidx.isValid()) {
        if (static_cast<unsigned>(row) < mTopLevels.size()) {
            return index(mTopLevels[row], col);
        } else if (static_cast<unsigned>(row) < mTopLevels.size() + mGroups.size()) {
            return index(mGroups[row - mTopLevels.size()], col);
        } else {
            return QModelIndex();
        }
    }

    // non-toplevel item - find the row'th subject of this key:
    const Key issuer = this->key(pidx);
    const char *const fpr = issuer.primaryFingerprint();
    if (!fpr || !*fpr) {
        return QModelIndex();
    }
    const Map::const_iterator it = mKeysByExistingParent.find(fpr);
    if (it == mKeysByExistingParent.end() || static_cast<unsigned>(row) >= it->second.size()) {
        return QModelIndex();
    }
    return index(it->second[row], col);
}

QModelIndex HierarchicalKeyListModel::parent(const QModelIndex &idx) const
{
    const Key key = this->key(idx);
    if (key.isNull() || key.isRoot()) {
        return {};
    }
    const std::vector<Key>::const_iterator it
        = Kleo::binary_find(mKeysByFingerprint.begin(), mKeysByFingerprint.end(),
                            cleanChainID(key), _detail::ByFingerprint<std::less>());
    return it != mKeysByFingerprint.end() ? index(*it) : QModelIndex();
}

Key HierarchicalKeyListModel::doMapToKey(const QModelIndex &idx) const
{

    if (!idx.isValid()) {
        return Key::null;
    }

    const char *const issuer_fpr = static_cast<const char *>(idx.internalPointer());
    if (!issuer_fpr || !*issuer_fpr) {
        // top-level:
        if (static_cast<unsigned>(idx.row()) >= mTopLevels.size()) {
            return Key::null;
        } else {
            return mTopLevels[idx.row()];
        }
    }

    // non-toplevel:
    const Map::const_iterator it
        = mKeysByExistingParent.find(issuer_fpr);
    if (it == mKeysByExistingParent.end() || static_cast<unsigned>(idx.row()) >= it->second.size()) {
        return Key::null;
    }
    return it->second[idx.row()];
}

QModelIndex HierarchicalKeyListModel::doMapFromKey(const Key &key, int col) const
{

    if (key.isNull()) {
        return {};
    }

    const char *issuer_fpr = cleanChainID(key);

    // we need to look in the toplevels list,...
    const std::vector<Key> *v = &mTopLevels;
    if (issuer_fpr && *issuer_fpr) {
        const std::map< std::string, std::vector<Key> >::const_iterator it
            = mKeysByExistingParent.find(issuer_fpr);
        // ...unless we find an existing parent:
        if (it != mKeysByExistingParent.end()) {
            v = &it->second;
        } else {
            issuer_fpr = nullptr;    // force internalPointer to zero for toplevels
        }
    }

    const std::vector<Key>::const_iterator it
        = std::lower_bound(v->begin(), v->end(), key, _detail::ByFingerprint<std::less>());
    if (it == v->end() || !_detail::ByFingerprint<std::equal_to>()(*it, key)) {
        return QModelIndex();
    }

    const unsigned int row = std::distance(v->begin(), it);
    return createIndex(row, col, const_cast<char * /* thanks, Trolls :/ */ >(issuer_fpr));
}

void HierarchicalKeyListModel::addKeyWithParent(const char *issuer_fpr, const Key &key)
{

    Q_ASSERT(issuer_fpr); Q_ASSERT(*issuer_fpr); Q_ASSERT(!key.isNull());

    std::vector<Key> &subjects = mKeysByExistingParent[issuer_fpr];

    // find insertion point:
    const std::vector<Key>::iterator it = std::lower_bound(subjects.begin(), subjects.end(), key, _detail::ByFingerprint<std::less>());
    const int row = std::distance(subjects.begin(), it);

    if (it != subjects.end() && qstricmp(it->primaryFingerprint(), key.primaryFingerprint()) == 0) {
        // exists -> replace
        *it = key;
        if (!modelResetInProgress()) {
            Q_EMIT dataChanged(createIndex(row, 0, const_cast<char *>(issuer_fpr)), createIndex(row, NumColumns - 1, const_cast<char *>(issuer_fpr)));
        }
    } else {
        // doesn't exist -> insert
        const std::vector<Key>::const_iterator pos = Kleo::binary_find(mKeysByFingerprint.begin(), mKeysByFingerprint.end(),
                                                                       issuer_fpr, _detail::ByFingerprint<std::less>());
        Q_ASSERT(pos != mKeysByFingerprint.end());
        if (!modelResetInProgress()) {
            beginInsertRows(index(*pos), row, row);
        }
        subjects.insert(it, key);
        if (!modelResetInProgress()) {
            endInsertRows();
        }
    }
}

void HierarchicalKeyListModel::addKeyWithoutParent(const char *issuer_fpr, const Key &key)
{

    Q_ASSERT(issuer_fpr); Q_ASSERT(*issuer_fpr); Q_ASSERT(!key.isNull());

    std::vector<Key> &subjects = mKeysByNonExistingParent[issuer_fpr];

    // find insertion point:
    const std::vector<Key>::iterator it = std::lower_bound(subjects.begin(), subjects.end(), key, _detail::ByFingerprint<std::less>());

    if (it != subjects.end() && qstricmp(it->primaryFingerprint(), key.primaryFingerprint()) == 0)
        // exists -> replace
    {
        *it = key;
    } else
        // doesn't exist -> insert
    {
        subjects.insert(it, key);
    }

    addTopLevelKey(key);
}

void HierarchicalKeyListModel::addTopLevelKey(const Key &key)
{

    // find insertion point:
    const std::vector<Key>::iterator it = std::lower_bound(mTopLevels.begin(), mTopLevels.end(), key, _detail::ByFingerprint<std::less>());
    const int row = std::distance(mTopLevels.begin(), it);

    if (it != mTopLevels.end() && qstricmp(it->primaryFingerprint(), key.primaryFingerprint()) == 0) {
        // exists -> replace
        *it = key;
        if (!modelResetInProgress()) {
            Q_EMIT dataChanged(createIndex(row, 0), createIndex(row, NumColumns - 1));
        }
    } else {
        // doesn't exist -> insert
        if (!modelResetInProgress()) {
            beginInsertRows(QModelIndex(), row, row);
        }
        mTopLevels.insert(it, key);
        if (!modelResetInProgress()) {
            endInsertRows();
        }
    }

}

// sorts 'keys' such that parent always come before their children:
static std::vector<Key> topological_sort(const std::vector<Key> &keys)
{

    boost::adjacency_list<> graph(keys.size());

    // add edges from children to parents:
    for (unsigned int i = 0, end = keys.size(); i != end; ++i) {
        const char *const issuer_fpr = cleanChainID(keys[i]);
        if (!issuer_fpr || !*issuer_fpr) {
            continue;
        }
        const std::vector<Key>::const_iterator it
            = Kleo::binary_find(keys.begin(), keys.end(), issuer_fpr, _detail::ByFingerprint<std::less>());
        if (it == keys.end()) {
            continue;
        }
        add_edge(i, std::distance(keys.begin(), it), graph);
    }

    std::vector<int> order;
    order.reserve(keys.size());
    topological_sort(graph, std::back_inserter(order));

    Q_ASSERT(order.size() == keys.size());

    std::vector<Key> result;
    result.reserve(keys.size());
    for (int i : std::as_const(order)) {
        result.push_back(keys[i]);
    }
    return result;
}

QList<QModelIndex> HierarchicalKeyListModel::doAddKeys(const std::vector<Key> &keys)
{
    Q_ASSERT(std::is_sorted(keys.begin(), keys.end(), _detail::ByFingerprint<std::less>()));

    if (keys.empty()) {
        return QList<QModelIndex>();
    }

    const std::vector<Key> oldKeys = mKeysByFingerprint;

    std::vector<Key> merged;
    merged.reserve(keys.size() + mKeysByFingerprint.size());
    std::set_union(keys.begin(), keys.end(),
                   mKeysByFingerprint.begin(), mKeysByFingerprint.end(),
                   std::back_inserter(merged), _detail::ByFingerprint<std::less>());

    mKeysByFingerprint = merged;

    std::set<Key, _detail::ByFingerprint<std::less> > changedParents;

    const auto topologicalSortedList = topological_sort(keys);
    for (const Key &key : topologicalSortedList) {

        // check to see whether this key is a parent for a previously parent-less group:
        const char *const fpr = key.primaryFingerprint();
        if (!fpr || !*fpr) {
            continue;
        }

        const bool keyAlreadyExisted = std::binary_search(oldKeys.begin(), oldKeys.end(), key, _detail::ByFingerprint<std::less>());

        const Map::iterator it = mKeysByNonExistingParent.find(fpr);
        const std::vector<Key> children = it != mKeysByNonExistingParent.end() ? it->second : std::vector<Key>();
        if (it != mKeysByNonExistingParent.end()) {
            mKeysByNonExistingParent.erase(it);
        }

        // Step 1: For new keys, remove children from toplevel:

        if (!keyAlreadyExisted) {
            auto last = mTopLevels.begin();
            auto lastFP = mKeysByFingerprint.begin();

            for (const Key &k : std::as_const(children)) {
                last = Kleo::binary_find(last, mTopLevels.end(), k, _detail::ByFingerprint<std::less>());
                Q_ASSERT(last != mTopLevels.end());
                const int row = std::distance(mTopLevels.begin(), last);

                lastFP = Kleo::binary_find(lastFP, mKeysByFingerprint.end(), k, _detail::ByFingerprint<std::less>());
                Q_ASSERT(lastFP != mKeysByFingerprint.end());

                Q_EMIT rowAboutToBeMoved(QModelIndex(), row);
                if (!modelResetInProgress()) {
                    beginRemoveRows(QModelIndex(), row, row);
                }
                last = mTopLevels.erase(last);
                lastFP = mKeysByFingerprint.erase(lastFP);
                if (!modelResetInProgress()) {
                    endRemoveRows();
                }
            }
        }
        // Step 2: add/update key

        const char *const issuer_fpr = cleanChainID(key);
        if (!issuer_fpr || !*issuer_fpr)
            // root or something...
        {
            addTopLevelKey(key);
        } else if (std::binary_search(mKeysByFingerprint.begin(), mKeysByFingerprint.end(), issuer_fpr, _detail::ByFingerprint<std::less>()))
            // parent exists...
        {
            addKeyWithParent(issuer_fpr, key);
        } else
            // parent doesn't exist yet...
        {
            addKeyWithoutParent(issuer_fpr, key);
        }

        const QModelIndex key_idx = index(key);
        QModelIndex key_parent = key_idx.parent();
        while (key_parent.isValid()) {
            changedParents.insert(doMapToKey(key_parent));
            key_parent = key_parent.parent();
        }

        // Step 3: Add children to new parent ( == key )

        if (!keyAlreadyExisted && !children.empty()) {
            addKeys(children);
            const QModelIndex new_parent = index(key);
            // Q_EMIT the rowMoved() signals in reversed direction, so the
            // implementation can use a stack for mapping.
            for (int i = children.size() - 1; i >= 0; --i) {
                Q_EMIT rowMoved(new_parent, i);
            }
        }
    }
    //Q_EMIT dataChanged for all parents with new children. This triggers KeyListSortFilterProxyModel to
    //show a parent node if it just got children matching the proxy's filter
    if (!modelResetInProgress()) {
        for (const Key &i : std::as_const(changedParents)) {
            const QModelIndex idx = index(i);
            if (idx.isValid()) {
                Q_EMIT dataChanged(idx.sibling(idx.row(), 0), idx.sibling(idx.row(), NumColumns - 1));
            }
        }
    }
    return indexes(keys);
}

void HierarchicalKeyListModel::doRemoveKey(const Key &key)
{
    const QModelIndex idx = index(key);
    if (!idx.isValid()) {
        return;
    }

    const char *const fpr = key.primaryFingerprint();
    if (mKeysByExistingParent.find(fpr) != mKeysByExistingParent.end()) {
        //handle non-leave nodes:
        std::vector<Key> keys = mKeysByFingerprint;
        const std::vector<Key>::iterator it = Kleo::binary_find(keys.begin(), keys.end(),
                                                                key, _detail::ByFingerprint<std::less>());
        if (it == keys.end()) {
            return;
        }
        keys.erase(it);
        // FIXME for simplicity, we just clear the model and re-add all keys minus the removed one. This is suboptimal,
        // but acceptable given that deletion of non-leave nodes is rather rare.
        clear(Keys);
        addKeys(keys);
        return;
    }

    //handle leave nodes:

    const std::vector<Key>::iterator it = Kleo::binary_find(mKeysByFingerprint.begin(), mKeysByFingerprint.end(),
                                                            key, _detail::ByFingerprint<std::less>());

    Q_ASSERT(it != mKeysByFingerprint.end());
    Q_ASSERT(mKeysByNonExistingParent.find(fpr) == mKeysByNonExistingParent.end());
    Q_ASSERT(mKeysByExistingParent.find(fpr) == mKeysByExistingParent.end());

    if (!modelResetInProgress()) {
        beginRemoveRows(parent(idx), idx.row(), idx.row());
    }
    mKeysByFingerprint.erase(it);

    const char *const issuer_fpr = cleanChainID(key);

    const std::vector<Key>::iterator tlIt = Kleo::binary_find(mTopLevels.begin(), mTopLevels.end(),
                                                              key, _detail::ByFingerprint<std::less>());
    if (tlIt != mTopLevels.end()) {
        mTopLevels.erase(tlIt);
    }

    if (issuer_fpr && *issuer_fpr) {
        const Map::iterator nexIt = mKeysByNonExistingParent.find(issuer_fpr);
        if (nexIt != mKeysByNonExistingParent.end()) {
            const std::vector<Key>::iterator eit = Kleo::binary_find(nexIt->second.begin(), nexIt->second.end(),
                                                                     key, _detail::ByFingerprint<std::less>());
            if (eit != nexIt->second.end()) {
                nexIt->second.erase(eit);
            }
            if (nexIt->second.empty()) {
                mKeysByNonExistingParent.erase(nexIt);
            }
        }

        const Map::iterator exIt = mKeysByExistingParent.find(issuer_fpr);
        if (exIt != mKeysByExistingParent.end()) {
            const std::vector<Key>::iterator eit = Kleo::binary_find(exIt->second.begin(), exIt->second.end(),
                                                                     key, _detail::ByFingerprint<std::less>());
            if (eit != exIt->second.end()) {
                exIt->second.erase(eit);
            }
            if (exIt->second.empty()) {
                mKeysByExistingParent.erase(exIt);
            }
        }
    }
    if (!modelResetInProgress()) {
        endRemoveRows();
    }
}

KeyGroup HierarchicalKeyListModel::doMapToGroup(const QModelIndex &idx) const
{
    Q_ASSERT(idx.isValid());
    if (idx.parent().isValid()) {
        // groups are always top-level
        return KeyGroup();
    }

    if (static_cast<unsigned>(idx.row()) >= mTopLevels.size()
            && static_cast<unsigned>(idx.row()) < mTopLevels.size() + mGroups.size()
            && idx.column() < NumColumns) {
        return mGroups[ idx.row() - mTopLevels.size() ];
    } else {
        return KeyGroup();
    }
}

QModelIndex HierarchicalKeyListModel::doMapFromGroup(const KeyGroup &group, int column) const
{
    Q_ASSERT(!group.isNull());
    const auto it = std::find_if(mGroups.cbegin(), mGroups.cend(),
                                 [group](const KeyGroup &g) {
                                     return g.source() == group.source() && g.id() == group.id();
                                 });
    if (it == mGroups.cend()) {
        return QModelIndex();
    } else {
        return createIndex(it - mGroups.cbegin() + mTopLevels.size(), column);
    }
}

void HierarchicalKeyListModel::doSetGroups(const std::vector<KeyGroup> &groups)
{
    Q_ASSERT(mGroups.empty());  // ensure that groups have been cleared
    const int first = mTopLevels.size();
    const int last = first + groups.size() - 1;
    if (!modelResetInProgress()) {
        beginInsertRows(QModelIndex(), first, last);
    }
    mGroups = groups;
    if (!modelResetInProgress()) {
        endInsertRows();
    }
}

QModelIndex HierarchicalKeyListModel::doAddGroup(const KeyGroup &group)
{
    const int newRow = lastGroupRow() + 1;
    if (!modelResetInProgress()) {
        beginInsertRows(QModelIndex(), newRow, newRow);
    }
    mGroups.push_back(group);
    if (!modelResetInProgress()) {
        endInsertRows();
    }
    return createIndex(newRow, 0);
}

bool HierarchicalKeyListModel::doSetGroupData(const QModelIndex &index, const KeyGroup &group)
{
    if (group.isNull()) {
        return false;
    }
    const int groupIndex = this->groupIndex(index);
    if (groupIndex == -1) {
        return false;
    }
    mGroups[groupIndex] = group;
    if (!modelResetInProgress()) {
        Q_EMIT dataChanged(createIndex(index.row(), 0), createIndex(index.row(), NumColumns - 1));
    }
    return true;
}

bool HierarchicalKeyListModel::doRemoveGroup(const KeyGroup &group)
{
    const QModelIndex modelIndex = doMapFromGroup(group, 0);
    if (!modelIndex.isValid()) {
        return false;
    }
    const int groupIndex = this->groupIndex(modelIndex);
    Q_ASSERT(groupIndex != -1);
    if (groupIndex == -1) {
        return false;
    }
    if (!modelResetInProgress()) {
        beginRemoveRows(QModelIndex(), modelIndex.row(), modelIndex.row());
    }
    mGroups.erase(mGroups.begin() + groupIndex);
    if (!modelResetInProgress()) {
        endRemoveRows();
    }
    return true;
}

void AbstractKeyListModel::useKeyCache(bool value, KeyList::Options options)
{
    d->m_keyListOptions = options;
    d->m_useKeyCache = value;
    if (!d->m_useKeyCache) {
        clear(All);
    } else {
        d->updateFromKeyCache();
    }
    connect(KeyCache::instance().get(), &KeyCache::keysMayHaveChanged,
            this, [this] { d->updateFromKeyCache(); });
}

// static
AbstractKeyListModel *AbstractKeyListModel::createFlatKeyListModel(QObject *p)
{
    AbstractKeyListModel *const m = new FlatKeyListModel(p);
#ifdef KLEO_MODEL_TEST
    new QAbstractItemModelTester(m, p);
#endif
    return m;
}

// static
AbstractKeyListModel *AbstractKeyListModel::createHierarchicalKeyListModel(QObject *p)
{
    AbstractKeyListModel *const m = new HierarchicalKeyListModel(p);
#ifdef KLEO_MODEL_TEST
    new QAbstractItemModelTester(m, p);
#endif
    return m;
}

#include "keylistmodel.moc"

/*!
  \fn AbstractKeyListModel::rowAboutToBeMoved( const QModelIndex & old_parent, int old_row )

  Emitted before the removal of a row from that model. It will later
  be added to the model again, in response to which rowMoved() will be
  emitted. If multiple rows are moved in one go, multiple
  rowAboutToBeMoved() signals are emitted before the corresponding
  number of rowMoved() signals is emitted - in reverse order.

  This works around the absence of move semantics in
  QAbstractItemModel. Clients can maintain a stack to perform the
  QModelIndex-mapping themselves, or, e.g., to preserve the selection
  status of the row:

  \code
  std::vector<bool> mMovingRowWasSelected; // transient, used when rows are moved
  // ...
  void slotRowAboutToBeMoved( const QModelIndex & p, int row ) {
      mMovingRowWasSelected.push_back( selectionModel()->isSelected( model()->index( row, 0, p ) ) );
  }
  void slotRowMoved( const QModelIndex & p, int row ) {
      const bool wasSelected = mMovingRowWasSelected.back();
      mMovingRowWasSelected.pop_back();
      if ( wasSelected )
          selectionModel()->select( model()->index( row, 0, p ), Select|Rows );
  }
  \endcode

  A similar mechanism could be used to preserve the current item during moves.
*/

/*!
  \fn AbstractKeyListModel::rowMoved( const QModelIndex & new_parent, int new_parent )

  See rowAboutToBeMoved()
*/
