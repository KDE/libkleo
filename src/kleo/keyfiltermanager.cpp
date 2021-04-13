/*
    keyfiltermanager.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "keyfiltermanager.h"
#include "kconfigbasedkeyfilter.h"
#include "defaultkeyfilter.h"

#include "stl_util.h"

#include "libkleo_debug.h"
#include "utils/formatting.h"

#include <KConfig>
#include <KConfigGroup>
#include <KSharedConfig>
#include <KLocalizedString>
#include <QIcon>

#include <QCoreApplication>
#include <QRegularExpression>
#include <QStringList>
#include <QAbstractListModel>
#include <QModelIndex>

#include <algorithm>
#include <climits>
#include <functional>

using namespace Kleo;
using namespace GpgME;

namespace
{

class Model : public QAbstractListModel
{
    KeyFilterManager::Private *m_keyFilterManagerPrivate;
public:
    explicit Model(KeyFilterManager::Private *p)
        : QAbstractListModel(nullptr), m_keyFilterManagerPrivate(p) {}

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
        setName(i18n("All Certificates"));
        setId(QStringLiteral("all-certificates"));
        setMatchContexts(Filtering);
    }
};

class MyCertificatesKeyFilter : public DefaultKeyFilter
{
public:
    MyCertificatesKeyFilter()
        : DefaultKeyFilter()
    {
        setHasSecret(Set);
        setSpecificity(UINT_MAX - 1); // overly high for ordering

        setName(i18n("My Certificates"));
        setId(QStringLiteral("my-certificates"));
        setMatchContexts(AnyMatchContext);
        setBold(true);
    }
};

class TrustedCertificatesKeyFilter : public DefaultKeyFilter
{
public:
    TrustedCertificatesKeyFilter()
        : DefaultKeyFilter()
    {
        setRevoked(NotSet);
        setValidity(IsAtLeast);
        setValidityReferenceLevel(UserID::Marginal);
        setSpecificity(UINT_MAX - 2); // overly high for ordering

        setName(i18n("Trusted Certificates"));
        setId(QStringLiteral("trusted-certificates"));
        setMatchContexts(Filtering);
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
        setSpecificity(UINT_MAX - 3);

        setName(i18n("Fully Trusted Certificates"));
        setId(QStringLiteral("full-certificates"));
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
        setValidityReferenceLevel(UserID::Never);
        setSpecificity(UINT_MAX - 4); // overly high for ordering

        setName(i18n("Other Certificates"));
        setId(QStringLiteral("other-certificates"));
        setMatchContexts(Filtering);
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
        setName(i18n("Not validated Certificates"));
        setId(QStringLiteral("not-validated-certificates"));
        setSpecificity(UINT_MAX - 6); // overly high for ordering
    }
    bool matches (const Key &key, MatchContexts contexts) const override
    {
        return (contexts & Filtering) && !Formatting::uidsHaveFullValidity(key);
    }
};

}

static std::vector<std::shared_ptr<KeyFilter>> defaultFilters()
{
    std::vector<std::shared_ptr<KeyFilter> > result;
    result.reserve(6);
    result.push_back(std::shared_ptr<KeyFilter>(new MyCertificatesKeyFilter));
    result.push_back(std::shared_ptr<KeyFilter>(new TrustedCertificatesKeyFilter));
    result.push_back(std::shared_ptr<KeyFilter>(new FullCertificatesKeyFilter));
    result.push_back(std::shared_ptr<KeyFilter>(new OtherCertificatesKeyFilter));
    result.push_back(std::shared_ptr<KeyFilter>(new AllCertificatesKeyFilter));
    result.push_back(std::shared_ptr<KeyFilter>(new KeyNotValidFilter));
    return result;
}

class KeyFilterManager::Private
{
public:
    Private() : filters(), model(this) {}
    void clear()
    {
        model.beginResetModel();
        filters.clear();
        model.endResetModel();
    }

    std::vector<std::shared_ptr<KeyFilter>> filters;
    Model model;
};

KeyFilterManager *KeyFilterManager::mSelf = nullptr;

KeyFilterManager::KeyFilterManager(QObject *parent)
    : QObject(parent), d(new Private)
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
        d->clear();
    }
    delete d; d = nullptr;
}

KeyFilterManager *KeyFilterManager::instance()
{
    if (!mSelf) {
        mSelf = new KeyFilterManager();
    }
    return mSelf;
}

const std::shared_ptr<KeyFilter> &KeyFilterManager::filterMatching(const Key &key, KeyFilter::MatchContexts contexts) const
{
    const auto it = std::find_if(d->filters.cbegin(), d->filters.cend(),
                                 [&key, contexts](const std::shared_ptr<KeyFilter> &filter) {
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
    std::remove_copy_if(d->filters.begin(), d->filters.end(),
                        std::back_inserter(result),
                        [&key, contexts](const std::shared_ptr<KeyFilter> &filter) {
                            return !filter->matches(key, contexts);
                        });
    return result;
}

namespace
{
struct ByDecreasingSpecificity : std::binary_function<std::shared_ptr<KeyFilter>, std::shared_ptr<KeyFilter>, bool> {
    bool operator()(const std::shared_ptr<KeyFilter> &lhs, const std::shared_ptr<KeyFilter> &rhs) const
    {
        return lhs->specificity() > rhs->specificity();
    }
};
}

void KeyFilterManager::reload()
{
    d->clear();

    d->filters = defaultFilters();
    KSharedConfigPtr config = KSharedConfig::openConfig(QStringLiteral("libkleopatrarc"));

    const QStringList groups = config->groupList().filter(QRegularExpression(QStringLiteral("^Key Filter #\\d+$")));
    bool ignoreDeVs = Formatting::complianceMode() != QLatin1String("de-vs");
    for (QStringList::const_iterator it = groups.begin(); it != groups.end(); ++it) {
        const KConfigGroup cfg(config, *it);
        if (cfg.hasKey("is-de-vs") && ignoreDeVs) {
            /* Don't show de-vs filters in other compliance modes */
            continue;
        }
        d->filters.push_back(std::shared_ptr<KeyFilter>(new KConfigBasedKeyFilter(cfg)));
    }
    std::stable_sort(d->filters.begin(), d->filters.end(), ByDecreasingSpecificity());
    qCDebug(LIBKLEO_LOG) << "final filter count is" << d->filters.size();
}

QAbstractItemModel *KeyFilterManager::model() const
{
    return &d->model;
}

const std::shared_ptr<KeyFilter> &KeyFilterManager::keyFilterByID(const QString &id) const
{
    const auto it = std::find_if(d->filters.begin(), d->filters.end(),
                                 [id](const std::shared_ptr<KeyFilter> &filter) {
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
    if (!idx.isValid() || idx.model() != &d->model || idx.row() < 0 ||
            static_cast<unsigned>(idx.row()) >= d->filters.size()) {
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
    const auto pair = std::equal_range(d->filters.cbegin(), d->filters.cend(), kf, ByDecreasingSpecificity());
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
    if (!idx.isValid()
        || idx.model() != this
        || idx.row() < 0
        || static_cast<unsigned>(idx.row()) >  m_keyFilterManagerPrivate->filters.size()) {
        return QVariant();
    }

    const auto filter = m_keyFilterManagerPrivate->filters[idx.row()];
    switch (role) {
    case Qt::DecorationRole:
        return filter->icon();

    case Qt::DisplayRole:
    case Qt::EditRole:
    case Qt::ToolTipRole:  /* Most useless tooltip ever.  */
        return filter->name();

    case KeyFilterManager::FilterIdRole:
        return filter->id();

    case KeyFilterManager::FilterMatchContextsRole:
        return QVariant::fromValue(filter->availableMatchContexts());

    default:
        return QVariant();
    }
}

static KeyFilter::FontDescription get_fontdescription(const std::vector<std::shared_ptr<KeyFilter>> &filters, const Key &key, const KeyFilter::FontDescription &initial)
{
    return kdtools::accumulate_if(filters.begin(), filters.end(),
                                  [&key](const std::shared_ptr<KeyFilter> &filter) {
                                      return filter->matches(key, KeyFilter::Appearance);
                                  },
                                  initial,
                                  [](const KeyFilter::FontDescription &lhs,
                                     const std::shared_ptr<KeyFilter> &rhs) {
                                      return lhs.resolve(rhs->fontDescription());
                                  });
}

QFont KeyFilterManager::font(const Key &key, const QFont &baseFont) const
{
    const KeyFilter::FontDescription fd = get_fontdescription(d->filters, key, KeyFilter::FontDescription());

    return fd.font(baseFont);
}

static QColor get_color(const std::vector<std::shared_ptr<KeyFilter>> &filters, const Key &key, QColor(KeyFilter::*fun)() const)
{
    const auto it = std::find_if(filters.cbegin(), filters.cend(),
                                 [&fun, &key](const std::shared_ptr<KeyFilter> &filter) {
                                    return filter->matches(key, KeyFilter::Appearance)
                                    && (filter.get()->*fun)().isValid();
                                 });
    if (it == filters.cend()) {
        return {};
    } else {
        return (it->get()->*fun)();
    }
}

static QString get_string(const std::vector<std::shared_ptr<KeyFilter>> &filters, const Key &key, QString(KeyFilter::*fun)() const)
{
    const auto it = std::find_if(filters.cbegin(), filters.cend(),
                                 [&fun, &key](const std::shared_ptr<KeyFilter> &filter) {
                                     return filter->matches(key, KeyFilter::Appearance)
                                            && !(filter.get()->*fun)().isEmpty();
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

QIcon KeyFilterManager::icon(const Key &key) const
{
    const QString icon = get_string(d->filters, key, &KeyFilter::icon);
    return icon.isEmpty() ? QIcon() : QIcon::fromTheme(icon);
}
