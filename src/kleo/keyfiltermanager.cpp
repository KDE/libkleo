/*
    keyfiltermanager.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    Copyright (c) 2004 Klarälvdalens Datakonsult AB

    Libkleopatra is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    Libkleopatra is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    In addition, as a special exception, the copyright holders give
    permission to link the code of this program with any edition of
    the Qt library by Trolltech AS, Norway (or with modified versions
    of Qt that use the same license as Qt), and distribute linked
    combinations including the two.  You must obey the GNU General
    Public License in all respects for all of the code used other than
    Qt.  If you modify this file, you may extend this exception to
    your version of the file, but you are not obligated to do so.  If
    you do not wish to do so, delete this exception statement from
    your version.
*/

#include "keyfiltermanager.h"
#include "kconfigbasedkeyfilter.h"
#include "defaultkeyfilter.h"

#include "stl_util.h"

#include "libkleo_debug.h"

#include <kconfig.h>
#include <kconfiggroup.h>
#include <KSharedConfig>
#include <KLocalizedString>
#include <QIcon>
#include <QDebug>

#include <QCoreApplication>
#include <QRegularExpression>
#include <QStringList>
#include <QAbstractListModel>
#include <QModelIndex>

#include <algorithm>
#include <vector>
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

    int rowCount(const QModelIndex &) const Q_DECL_OVERRIDE;
    QVariant data(const QModelIndex &idx, int role) const Q_DECL_OVERRIDE;
    /* upgrade to public */ using QAbstractListModel::reset;
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
        setValidityReferenceLevel(UserID::Marginal); // Full?
        setSpecificity(UINT_MAX - 2); // overly high for ordering

        setName(i18n("Trusted Certificates"));
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
        setValidityReferenceLevel(UserID::Never);
        setSpecificity(UINT_MAX - 3); // overly high for ordering

        setName(i18n("Other Certificates"));
        setId(QStringLiteral("other-certificates"));
        setMatchContexts(Filtering);
    }
};
}

static std::vector<std::shared_ptr<KeyFilter>> defaultFilters()
{
    std::vector<std::shared_ptr<KeyFilter> > result;
    result.reserve(3);
    result.push_back(std::shared_ptr<KeyFilter>(new MyCertificatesKeyFilter));
    result.push_back(std::shared_ptr<KeyFilter>(new TrustedCertificatesKeyFilter));
    result.push_back(std::shared_ptr<KeyFilter>(new OtherCertificatesKeyFilter));
    result.push_back(std::shared_ptr<KeyFilter>(new AllCertificatesKeyFilter));
    return result;
}

class KeyFilterManager::Private
{
public:
    Private() : filters(), model(this) {}
    void clear()
    {
        filters.clear();
        model.reset();
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
    for (QStringList::const_iterator it = groups.begin(); it != groups.end(); ++it) {
        const KConfigGroup cfg(config, *it);
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
        return QModelIndex();
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
    if ((role != Qt::DisplayRole && role != Qt::EditRole &&
            role != Qt::ToolTipRole && role != Qt::DecorationRole) ||
            !idx.isValid() || idx.model() != this ||
            idx.row() < 0 || static_cast<unsigned>(idx.row()) >  m_keyFilterManagerPrivate->filters.size()) {
        return QVariant();
    }
    if (role == Qt::DecorationRole) {
        return m_keyFilterManagerPrivate->filters[idx.row()]->icon();
    } else {
        return m_keyFilterManagerPrivate->filters[idx.row()]->name();
    }
}

QFont KeyFilterManager::font(const Key &key, const QFont &baseFont) const
{
    return kdtools::accumulate_if(d->filters.begin(), d->filters.end(),
                                  [&key](const std::shared_ptr<KeyFilter> &filter) {
                                      return filter->matches(key, KeyFilter::Appearance);
                                  },
                                  KeyFilter::FontDescription(),
                                  [](const KeyFilter::FontDescription &lhs,
                                     const std::shared_ptr<KeyFilter> &rhs) {
                                      return lhs.resolve(rhs->fontDescription());
                                  }).font(baseFont);
}

static QColor get_color(const std::vector<std::shared_ptr<KeyFilter>> &filters, const Key &key, QColor(KeyFilter::*fun)() const)
{
    const auto it = std::find_if(filters.cbegin(), filters.cend(),
                                 [&fun, &key](const std::shared_ptr<KeyFilter> &filter) {
                                    return filter->matches(key, KeyFilter::Appearance)
                                    && !(filter.get()->*fun)().isValid();
                                 });
    if (it == filters.cend()) {
        return QColor();
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

