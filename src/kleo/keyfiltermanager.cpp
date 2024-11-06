/*
    keyfiltermanager.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "keyfiltermanager.h"

#include "defaultkeyfilter.h"
#include "kconfigbasedkeyfilter.h"
#include "stl_util.h"

#include <libkleo/algorithm.h>
#include <libkleo/compliance.h>
#include <libkleo/gnupg.h>
#include <libkleo/keyhelpers.h>

#include <libkleo_debug.h>

#include <KConfig>
#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>

#include <QAbstractListModel>
#include <QCoreApplication>
#include <QIcon>
#include <QModelIndex>
#include <QRegularExpression>
#include <QStringList>

#include <algorithm>
#include <climits>
#include <functional>

using namespace Kleo;
using namespace GpgME;

namespace
{
void adjustFilters(std::vector<std::shared_ptr<KeyFilter>> &filters, Protocol protocol)
{
    if (protocol != GpgME::UnknownProtocol) {
        // remove filters with conflicting isOpenPGP rule
        const auto conflictingValue = (protocol == GpgME::OpenPGP) ? DefaultKeyFilter::NotSet : DefaultKeyFilter::Set;
        Kleo::erase_if(filters, [conflictingValue](const auto &f) {
            const auto filter = std::dynamic_pointer_cast<DefaultKeyFilter>(f);
            Q_ASSERT(filter);
            return filter->isOpenPGP() == conflictingValue;
        });
        // add isOpenPGP rule to all filters
        const auto isOpenPGPValue = (protocol == GpgME::OpenPGP) ? DefaultKeyFilter::Set : DefaultKeyFilter::NotSet;
        std::for_each(std::begin(filters), std::end(filters), [isOpenPGPValue](auto &f) {
            const auto filter = std::dynamic_pointer_cast<DefaultKeyFilter>(f);
            Q_ASSERT(filter);
            return filter->setIsOpenPGP(isOpenPGPValue);
        });
    }
}

class Model : public QAbstractListModel
{
    KeyFilterManager::Private *m_keyFilterManagerPrivate;

public:
    explicit Model(KeyFilterManager::Private *p)
        : QAbstractListModel(nullptr)
        , m_keyFilterManagerPrivate(p)
    {
    }

    int rowCount(const QModelIndex &) const override;
    QVariant data(const QModelIndex &idx, int role) const override;
    /* upgrade to public */ using QAbstractListModel::beginResetModel;
    /* upgrade to public */ using QAbstractListModel::endResetModel;
};

class AllCertificatesKeyFilter : public DefaultKeyFilter
{
public:
    AllCertificatesKeyFilter()
        : DefaultKeyFilter()
    {
        setSpecificity(UINT_MAX); // overly high for ordering
        setName(i18nc("All Certificates", "All"));
        setDescription(i18n("All certificates (except disabled ones)"));
        setId(QStringLiteral("all-certificates"));
        setMatchContexts(Filtering);
        setDisabled(NotSet);
    }
};

class MyCertificatesKeyFilter : public DefaultKeyFilter
{
public:
    MyCertificatesKeyFilter()
        : DefaultKeyFilter()
    {
        setHasSecret(Set);
        setSpecificity(UINT_MAX - 2); // overly high for ordering
        setDisabled(NotSet);

        setName(i18nc("My own Certificates", "My Own"));
        setDescription(i18n("My own certificates (except disabled ones)"));
        setId(QStringLiteral("my-certificates"));
        setMatchContexts(AnyMatchContext);
        setBold(true);
    }
};

class FullCertificatesKeyFilter : public DefaultKeyFilter
{
public:
    FullCertificatesKeyFilter()
        : DefaultKeyFilter()
    {
        setRevoked(NotSet);
        setValidity(IsAtLeast);
        setValidityReferenceLevel(UserID::Full);
        setSpecificity(UINT_MAX - 4);
        setDisabled(NotSet);

        setName(i18nc("Certified Certificates", "Certified"));
        setDescription(i18n("Certificates for which the primary user ID is certified (except disabled ones)"));
        setId(QStringLiteral("trusted-certificates"));
        setMatchContexts(Filtering);
    }
};

class OtherCertificatesKeyFilter : public DefaultKeyFilter
{
public:
    OtherCertificatesKeyFilter()
        : DefaultKeyFilter()
    {
        setHasSecret(NotSet);
        setValidity(IsAtMost);
        setValidityReferenceLevel(UserID::Marginal);
        setSpecificity(UINT_MAX - 6); // overly high for ordering
        setDisabled(NotSet);

        setName(i18nc("Not Certified Certificates", "Not Certified"));
        setDescription(i18n("Certificates for which the primary user ID is not certified (except disabled ones)"));
        setId(QStringLiteral("other-certificates"));
        setMatchContexts(Filtering);
    }
};

/* This filter selects uncertified OpenPGP keys, i.e. "good" OpenPGP keys with
 * unrevoked user IDs that are not fully valid. */
class UncertifiedOpenPGPKeysFilter : public DefaultKeyFilter
{
public:
    UncertifiedOpenPGPKeysFilter()
        : DefaultKeyFilter()
    {
        setSpecificity(UINT_MAX - 7); // overly high for ordering
        setName(i18nc("Certificates to certify by the user", "To Certify"));
        setDescription(i18n("Certificates that are not fully certified and that you may want to certify yourself (except disabled ones)"));
        setId(QStringLiteral("not-certified-certificates"));

        setMatchContexts(Filtering);
        setIsOpenPGP(Set);
        setIsBad(NotSet);
        setDisabled(NotSet);
    }
    bool matches(const Key &key, MatchContexts contexts) const override
    {
        return DefaultKeyFilter::matches(key, contexts) && !Kleo::allUserIDsHaveFullValidity(key);
    }
    bool matches(const UserID &userID, MatchContexts contexts) const override
    {
        return DefaultKeyFilter::matches(userID.parent(), contexts) && userID.validity() < UserID::Full;
    }
};

/* This filter selects only invalid keys (i.e. those where not all
 * UIDs are at least fully valid).  */
class KeyNotValidFilter : public DefaultKeyFilter
{
public:
    KeyNotValidFilter()
        : DefaultKeyFilter()
    {
        setSpecificity(UINT_MAX - 5); // overly high for ordering

        setName(i18nc("Not Fully Certified Certificates", "Not Fully Certified"));
        setDescription(i18n("Certificates for which not all user IDs are certified (except disabled ones)"));
        setId(QStringLiteral("not-validated-certificates"));
        setMatchContexts(Filtering);
        setDisabled(NotSet);
    }
    bool matches(const Key &key, MatchContexts contexts) const override
    {
        return DefaultKeyFilter::matches(key, contexts) && !Kleo::allUserIDsHaveFullValidity(key);
    }
    bool matches(const UserID &userID, MatchContexts contexts) const override
    {
        return DefaultKeyFilter::matches(userID.parent(), contexts) && userID.validity() < UserID::Full;
    }
};

}

class KeyFullyCertifiedFilter : public DefaultKeyFilter
{
public:
    KeyFullyCertifiedFilter()
        : DefaultKeyFilter()
    {
        setSpecificity(UINT_MAX - 3);
        setName(i18nc("Fully Certified Certificates", "Fully Certified"));
        setDescription(i18n("Certificates for which all user IDs are certified (except disabled ones)"));
        setId(QStringLiteral("full-certificates"));
        setMatchContexts(Filtering);
        setDisabled(NotSet);
    }
    bool matches(const Key &key, MatchContexts contexts) const override
    {
        return DefaultKeyFilter::matches(key, contexts) && Kleo::allUserIDsHaveFullValidity(key);
    }
    bool matches(const UserID &userID, MatchContexts contexts) const override
    {
        return DefaultKeyFilter::matches(userID.parent(), contexts) && userID.validity() >= UserID::Full;
    }
};

static std::vector<std::shared_ptr<KeyFilter>> defaultFilters()
{
    return {
        std::shared_ptr<KeyFilter>(new MyCertificatesKeyFilter),
        std::shared_ptr<KeyFilter>(new FullCertificatesKeyFilter),
        std::shared_ptr<KeyFilter>(new OtherCertificatesKeyFilter),
        std::shared_ptr<KeyFilter>(new AllCertificatesKeyFilter),
        std::shared_ptr<KeyFilter>(new UncertifiedOpenPGPKeysFilter),
        std::shared_ptr<KeyFilter>(new KeyFullyCertifiedFilter),
        std::shared_ptr<KeyFilter>(new KeyNotValidFilter),
    };
}

class KeyFilterManager::Private
{
public:
    Private()
        : filters()
        , model(this)
    {
    }
    void clear()
    {
        filters.clear();
    }

    std::vector<std::shared_ptr<KeyFilter>> filters;
    Model model;
    GpgME::Protocol protocol = GpgME::UnknownProtocol;
};

KeyFilterManager *KeyFilterManager::mSelf = nullptr;

KeyFilterManager::KeyFilterManager(QObject *parent)
    : QObject(parent)
    , d(new Private)
{
    mSelf = this;
    // ### DF: doesn't a KStaticDeleter work more reliably?
    if (QCoreApplication *app = QCoreApplication::instance()) {
        connect(app, &QCoreApplication::aboutToQuit, this, &QObject::deleteLater);
    }
    reload();
}

KeyFilterManager::~KeyFilterManager()
{
    mSelf = nullptr;
    if (d) {
        d->model.beginResetModel();
        d->clear();
        d->model.endResetModel();
    }
}

KeyFilterManager *KeyFilterManager::instance()
{
    if (!mSelf) {
        mSelf = new KeyFilterManager();
    }
    return mSelf;
}

void KeyFilterManager::alwaysFilterByProtocol(GpgME::Protocol protocol)
{
    if (protocol != d->protocol) {
        d->protocol = protocol;
        reload();
        Q_EMIT alwaysFilterByProtocolChanged(protocol);
    }
}

const std::shared_ptr<KeyFilter> &KeyFilterManager::filterMatching(const Key &key, KeyFilter::MatchContexts contexts) const
{
    const auto it = std::find_if(d->filters.cbegin(), d->filters.cend(), [&key, contexts](const std::shared_ptr<KeyFilter> &filter) {
        return filter->matches(key, contexts);
    });
    if (it != d->filters.cend()) {
        return *it;
    }
    static const std::shared_ptr<KeyFilter> null;
    return null;
}

std::vector<std::shared_ptr<KeyFilter>> KeyFilterManager::filtersMatching(const Key &key, KeyFilter::MatchContexts contexts) const
{
    std::vector<std::shared_ptr<KeyFilter>> result;
    result.reserve(d->filters.size());
    std::remove_copy_if(d->filters.begin(), d->filters.end(), std::back_inserter(result), [&key, contexts](const std::shared_ptr<KeyFilter> &filter) {
        return !filter->matches(key, contexts);
    });
    return result;
}

namespace
{
static const auto byDecreasingSpecificity = [](const std::shared_ptr<KeyFilter> &lhs, const std::shared_ptr<KeyFilter> &rhs) {
    return lhs->specificity() > rhs->specificity();
};
}

void KeyFilterManager::reload()
{
    d->model.beginResetModel();
    d->clear();

    d->filters = defaultFilters();
    KSharedConfigPtr config = KSharedConfig::openConfig(QStringLiteral("libkleopatrarc"));

    const QStringList groups = config->groupList().filter(QRegularExpression(QStringLiteral("^Key Filter #\\d+$")));
    const bool ignoreDeVs = !DeVSCompliance::isCompliant();
    for (QStringList::const_iterator it = groups.begin(); it != groups.end(); ++it) {
        const KConfigGroup cfg(config, *it);
        if (cfg.hasKey("is-de-vs") && ignoreDeVs) {
            /* Don't show de-vs filters in other compliance modes */
            continue;
        }
        d->filters.push_back(std::shared_ptr<KeyFilter>(new KConfigBasedKeyFilter(cfg)));
    }
    std::stable_sort(d->filters.begin(), d->filters.end(), byDecreasingSpecificity);

    adjustFilters(d->filters, d->protocol);
    d->model.endResetModel();
    qCDebug(LIBKLEO_LOG) << "KeyFilterManager::" << __func__ << "final filter count is" << d->filters.size();
}

QAbstractItemModel *KeyFilterManager::model() const
{
    return &d->model;
}

const std::shared_ptr<KeyFilter> &KeyFilterManager::keyFilterByID(const QString &id) const
{
    const auto it = std::find_if(d->filters.begin(), d->filters.end(), [id](const std::shared_ptr<KeyFilter> &filter) {
        return filter->id() == id;
    });
    if (it != d->filters.end()) {
        return *it;
    }
    static const std::shared_ptr<KeyFilter> null;
    return null;
}

const std::shared_ptr<KeyFilter> &KeyFilterManager::fromModelIndex(const QModelIndex &idx) const
{
    if (!idx.isValid() || idx.model() != &d->model || idx.row() < 0 || static_cast<unsigned>(idx.row()) >= d->filters.size()) {
        static const std::shared_ptr<KeyFilter> null;
        return null;
    }
    return d->filters[idx.row()];
}

QModelIndex KeyFilterManager::toModelIndex(const std::shared_ptr<KeyFilter> &kf) const
{
    if (!kf) {
        return {};
    }
    const auto pair = std::equal_range(d->filters.cbegin(), d->filters.cend(), kf, byDecreasingSpecificity);
    const auto it = std::find(pair.first, pair.second, kf);
    if (it != pair.second) {
        return d->model.index(it - d->filters.begin());
    } else {
        return QModelIndex();
    }
}

int Model::rowCount(const QModelIndex &) const
{
    return m_keyFilterManagerPrivate->filters.size();
}

QVariant Model::data(const QModelIndex &idx, int role) const
{
    if (!idx.isValid() || idx.model() != this || idx.row() < 0 || static_cast<unsigned>(idx.row()) > m_keyFilterManagerPrivate->filters.size()) {
        return QVariant();
    }

    const auto filter = m_keyFilterManagerPrivate->filters[idx.row()];
    switch (role) {
    case Qt::DecorationRole:
        return filter->icon();

    case Qt::DisplayRole:
    case Qt::EditRole:
        return filter->name();
    case Qt::ToolTipRole:
        return filter->description();

    case KeyFilterManager::FilterIdRole:
        return filter->id();

    case KeyFilterManager::FilterMatchContextsRole:
        return QVariant::fromValue(filter->availableMatchContexts());

    case KeyFilterManager::FilterRole:
        return QVariant::fromValue(filter);

    default:
        return QVariant();
    }
}

static KeyFilter::FontDescription
get_fontdescription(const std::vector<std::shared_ptr<KeyFilter>> &filters, const Key &key, const KeyFilter::FontDescription &initial)
{
    return kdtools::accumulate_if(
        filters.begin(),
        filters.end(),
        [&key](const std::shared_ptr<KeyFilter> &filter) {
            return filter->matches(key, KeyFilter::Appearance);
        },
        initial,
        [](const KeyFilter::FontDescription &lhs, const std::shared_ptr<KeyFilter> &rhs) {
            return lhs.resolve(rhs->fontDescription());
        });
}

QFont KeyFilterManager::font(const Key &key, const QFont &baseFont) const
{
    const KeyFilter::FontDescription fd = get_fontdescription(d->filters, key, KeyFilter::FontDescription());

    return fd.font(baseFont);
}

static QColor get_color(const std::vector<std::shared_ptr<KeyFilter>> &filters, const Key &key, QColor (KeyFilter::*fun)() const)
{
    const auto it = std::find_if(filters.cbegin(), filters.cend(), [&fun, &key](const std::shared_ptr<KeyFilter> &filter) {
        return filter->matches(key, KeyFilter::Appearance) && (filter.get()->*fun)().isValid();
    });
    if (it == filters.cend()) {
        return {};
    } else {
        return (it->get()->*fun)();
    }
}

static QColor get_color(const std::vector<std::shared_ptr<KeyFilter>> &filters, const UserID &userID, QColor (KeyFilter::*fun)() const)
{
    const auto it = std::find_if(filters.cbegin(), filters.cend(), [&fun, &userID](const std::shared_ptr<KeyFilter> &filter) {
        return filter->matches(userID, KeyFilter::Appearance) && (filter.get()->*fun)().isValid();
    });
    if (it == filters.cend()) {
        return {};
    } else {
        return (it->get()->*fun)();
    }
}

static QString get_string(const std::vector<std::shared_ptr<KeyFilter>> &filters, const Key &key, QString (KeyFilter::*fun)() const)
{
    const auto it = std::find_if(filters.cbegin(), filters.cend(), [&fun, &key](const std::shared_ptr<KeyFilter> &filter) {
        return filter->matches(key, KeyFilter::Appearance) && !(filter.get()->*fun)().isEmpty();
    });
    if (it == filters.cend()) {
        return QString();
    } else {
        return (*it)->icon();
    }
}

QColor KeyFilterManager::bgColor(const Key &key) const
{
    return get_color(d->filters, key, &KeyFilter::bgColor);
}

QColor KeyFilterManager::fgColor(const Key &key) const
{
    return get_color(d->filters, key, &KeyFilter::fgColor);
}

QColor KeyFilterManager::bgColor(const UserID &userID) const
{
    return get_color(d->filters, userID, &KeyFilter::bgColor);
}

QColor KeyFilterManager::fgColor(const UserID &userID) const
{
    return get_color(d->filters, userID, &KeyFilter::fgColor);
}

QIcon KeyFilterManager::icon(const Key &key) const
{
    const QString icon = get_string(d->filters, key, &KeyFilter::icon);
    return icon.isEmpty() ? QIcon() : QIcon::fromTheme(icon);
}

Protocol KeyFilterManager::protocol() const
{
    return d->protocol;
}

class KeyFilterModel::Private
{
    friend class KeyFilterModel;
    std::vector<std::shared_ptr<KeyFilter>> customFilters;
};

KeyFilterModel::KeyFilterModel(QObject *parent)
    : QSortFilterProxyModel(parent)
    , d(new Private)
{
    setSourceModel(KeyFilterManager::instance()->model());
    connect(KeyFilterManager::instance(), &KeyFilterManager::alwaysFilterByProtocolChanged, this, [this](auto protocol) {
        beginResetModel();
        adjustFilters(d->customFilters, protocol);
        endResetModel();
    });
}

KeyFilterModel::~KeyFilterModel() = default;

void KeyFilterModel::prependCustomFilter(const std::shared_ptr<KeyFilter> &filter)
{
    beginResetModel();
    d->customFilters.insert(d->customFilters.begin(), filter);
    adjustFilters(d->customFilters, KeyFilterManager::instance()->protocol());
    endResetModel();
}

bool KeyFilterModel::isCustomFilter(int row) const
{
    return (row >= 0) && (row < int(d->customFilters.size()));
}

int KeyFilterModel::rowCount(const QModelIndex &parent) const
{
    return d->customFilters.size() + QSortFilterProxyModel::rowCount(parent);
}

int KeyFilterModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent)
    // pretend that there is only one column to workaround a bug in
    // QAccessibleTable which provides the accessibility interface for the
    // pop-up of the combo box
    return 1;
}

QModelIndex KeyFilterModel::mapToSource(const QModelIndex &index) const
{
    if (!index.isValid()) {
        return {};
    }
    if (!isCustomFilter(index.row())) {
        const int sourceRow = index.row() - d->customFilters.size();
        return QSortFilterProxyModel::mapToSource(createIndex(sourceRow, index.column(), index.internalPointer()));
    }
    return {};
}

QModelIndex KeyFilterModel::mapFromSource(const QModelIndex &source_index) const
{
    const QModelIndex idx = QSortFilterProxyModel::mapFromSource(source_index);
    return createIndex(d->customFilters.size() + idx.row(), idx.column(), idx.internalPointer());
}

QModelIndex KeyFilterModel::index(int row, int column, const QModelIndex &parent) const
{
    if (row < 0 || row >= rowCount()) {
        return {};
    }
    if (row < int(d->customFilters.size())) {
        return createIndex(row, column, nullptr);
    } else {
        const QModelIndex mi = QSortFilterProxyModel::index(row - d->customFilters.size(), column, parent);
        return createIndex(row, column, mi.internalPointer());
    }
}

Qt::ItemFlags KeyFilterModel::flags(const QModelIndex &index) const
{
    Q_UNUSED(index)
    return Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemNeverHasChildren;
}

QModelIndex KeyFilterModel::parent(const QModelIndex &) const
{
    // Flat list
    return {};
}

QVariant KeyFilterModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid()) {
        return QVariant();
    }

    if (isCustomFilter(index.row())) {
        const auto filter = d->customFilters[index.row()];
        switch (role) {
        case Qt::DecorationRole:
            return filter->icon();

        case Qt::DisplayRole:
        case Qt::EditRole:
            return filter->name();
        case Qt::ToolTipRole:
            return filter->description();

        case KeyFilterManager::FilterIdRole:
            return filter->id();

        case KeyFilterManager::FilterMatchContextsRole:
            return QVariant::fromValue(filter->availableMatchContexts());

        case KeyFilterManager::FilterRole:
            return QVariant::fromValue(filter);

        default:
            return QVariant();
        }
    }

    return QSortFilterProxyModel::data(index, role);
}

#include "moc_keyfiltermanager.cpp"
