/*  This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "keyselectioncombo.h"
#include <kleo_ui_debug.h>

#include "kleo/dn.h"
#include "models/keylist.h"
#include "models/keylistmodel.h"
#include "models/keylistsortfilterproxymodel.h"
#include "models/keycache.h"
#include "utils/formatting.h"
#include "progressbar.h"
#include "kleo/defaultkeyfilter.h"

#include <gpgme++/key.h>

#include <QSortFilterProxyModel>
#include <QVector>
#include <QTimer>

#include <KLocalizedString>

using namespace Kleo;

Q_DECLARE_METATYPE(GpgME::Key)

namespace
{
class SortFilterProxyModel : public KeyListSortFilterProxyModel
{
    Q_OBJECT

public:
    using KeyListSortFilterProxyModel::KeyListSortFilterProxyModel;

    void setAlwaysAcceptedKey(const QString &fingerprint)
    {
        if (fingerprint == mFingerprint) {
            return;
        }
        mFingerprint = fingerprint;
        invalidate();
    }

protected:
    bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const override
    {
        if (!mFingerprint.isEmpty()) {
            const QModelIndex index = sourceModel()->index(source_row, 0, source_parent);
            const auto fingerprint = sourceModel()->data(index, KeyList::FingerprintRole).toString();
            if (fingerprint == mFingerprint) {
                return true;
            }
        }

        return KeyListSortFilterProxyModel::filterAcceptsRow(source_row, source_parent);
    }

private:
    QString mFingerprint;
};

class ProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

private:
    struct CustomItem {
        QIcon icon;
        QString text;
        QVariant data;
        QString toolTip;
    };
public:
    ProxyModel(QObject *parent = nullptr)
        : QSortFilterProxyModel(parent)
    {
    }

    ~ProxyModel() override
    {
        qDeleteAll(mFrontItems);
        qDeleteAll(mBackItems);
    }

    bool lessThan(const QModelIndex &left, const QModelIndex &right) const override
    {
        const auto leftKey =  sourceModel()->data(left, KeyList::KeyRole).value<GpgME::Key>();
        const auto rightKey = sourceModel()->data(right, KeyList::KeyRole).value<GpgME::Key>();
        if (leftKey.isNull()) {
            return false;
        }
        if (rightKey.isNull()) {
            return true;
        }
        // As we display UID(0) this is ok. We probably need a get Best UID at some point.
        const auto lUid = leftKey.userID(0);
        const auto rUid = rightKey.userID(0);
        if (lUid.isNull()) {
            return false;
        }
        if (rUid.isNull()) {
            return true;
        }
        int cmp = strcmp (lUid.id(), rUid.id());
        if (cmp) {
            return cmp < 0;
        }

        if (lUid.validity() == rUid.validity()) {
            /* Both are the same check which one is newer. */
            time_t oldTime = 0;
            for (const GpgME::Subkey &s: leftKey.subkeys()) {
                if (s.isRevoked() || s.isInvalid() || s.isDisabled()) {
                    continue;
                }
                if (s.creationTime() > oldTime) {
                    oldTime= s.creationTime();
                }
            }
            time_t newTime = 0;
            for (const GpgME::Subkey &s: rightKey.subkeys()) {
                if (s.isRevoked() || s.isInvalid() || s.isDisabled()) {
                    continue;
                }
                if (s.creationTime() > newTime) {
                    newTime = s.creationTime();
                }
            }
            return newTime < oldTime;
        }
        return lUid.validity() > rUid.validity();
    }

    bool isCustomItem(const int row) const
    {
        return row < mFrontItems.count() || row >= mFrontItems.count() + QSortFilterProxyModel::rowCount();
    }

    void prependItem(const QIcon &icon, const QString &text, const QVariant &data, const QString &toolTip)
    {
        beginInsertRows(QModelIndex(), 0, 0);
        mFrontItems.push_front(new CustomItem{ icon, text, data, toolTip });
        endInsertRows();
    }

    void appendItem(const QIcon &icon, const QString &text, const QVariant &data, const QString &toolTip)
    {
        beginInsertRows(QModelIndex(), rowCount(), rowCount());
        mBackItems.push_back(new CustomItem{ icon, text, data, toolTip });
        endInsertRows();
    }

    void removeCustomItem(const QVariant &data)
    {
        for (int i = 0; i < mFrontItems.count(); ++i) {
            if (mFrontItems[i]->data == data) {
                beginRemoveRows(QModelIndex(), i, i);
                delete mFrontItems.takeAt(i);
                endRemoveRows();
                return;
            }
        }
        for (int i = 0; i < mBackItems.count(); ++i) {
            if (mBackItems[i]->data == data) {
                const int index = mFrontItems.count() + QSortFilterProxyModel::rowCount() + i;
                beginRemoveRows(QModelIndex(), index, index);
                delete mBackItems.takeAt(i);
                endRemoveRows();
                return;
            }
        }
    }

    int rowCount(const QModelIndex &parent = QModelIndex()) const override
    {
        return mFrontItems.count() + QSortFilterProxyModel::rowCount(parent) + mBackItems.count();
    }

    QModelIndex mapToSource(const QModelIndex &index) const override
    {
        if (!isCustomItem(index.row())) {
            const int row = index.row() - mFrontItems.count();

            return sourceModel()->index(row, index.column());
        } else {
            return {};
        }
    }

    QModelIndex mapFromSource(const QModelIndex &source_index) const override
    {
        const QModelIndex idx = QSortFilterProxyModel::mapFromSource(source_index);
        return createIndex(mFrontItems.count() + idx.row(), idx.column(), idx.internalPointer());
    }

    QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const override
    {
        if (row < 0 || row >= rowCount()) {
            return {};
        }
        if (row < mFrontItems.count()) {
            return createIndex(row, column, mFrontItems[row]);
        } else if (row >= mFrontItems.count() + QSortFilterProxyModel::rowCount()) {
            return createIndex(row, column, mBackItems[row - mFrontItems.count() - QSortFilterProxyModel::rowCount()]);
        } else {
            const QModelIndex mi = QSortFilterProxyModel::index(row - mFrontItems.count(), column, parent);
            return createIndex(row, column, mi.internalPointer());
        }
    }

    Qt::ItemFlags flags(const QModelIndex &index) const override
    {
        Q_UNUSED(index)
        return Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemNeverHasChildren;
    }

    QModelIndex parent(const QModelIndex &) const override
    {
        // Flat list
        return {};
    }

    QVariant data(const QModelIndex &index, int role) const override
    {
        if (!index.isValid()) {
            return QVariant();
        }

        if (isCustomItem(index.row())) {
            Q_ASSERT(!mFrontItems.isEmpty() || !mBackItems.isEmpty());
            auto ci = static_cast<CustomItem*>(index.internalPointer());
            switch (role) {
            case Qt::DisplayRole:
                return ci->text;
            case Qt::DecorationRole:
                return ci->icon;
            case Qt::UserRole:
                return ci->data;
            case Qt::ToolTipRole:
                return ci->toolTip;
            default:
                return QVariant();
            }
        }

        const auto key = QSortFilterProxyModel::data(index, KeyList::KeyRole).value<GpgME::Key>();
        Q_ASSERT(!key.isNull());
        if (key.isNull()) {
            return QVariant();
        }

        switch (role) {
        case Qt::DisplayRole: {
            const auto userID = key.userID(0);
            QString name, email;

            if (key.protocol() == GpgME::OpenPGP) {
                name = QString::fromUtf8(userID.name());
                email = QString::fromUtf8(userID.email());
            } else {
                const Kleo::DN dn(userID.id());
                name = dn[QStringLiteral("CN")];
                email = dn[QStringLiteral("EMAIL")];
            }
            return i18nc("Name <email> (validity, type, created: date)", "%1 (%2, %3 created: %4)",
                         email.isEmpty() ? name : name.isEmpty() ? email : i18nc("Name <email>", "%1 <%2>", name, email),
                         Kleo::Formatting::complianceStringShort(key),
                         Kleo::KeyCache::instance()->pgpOnly() ? QString() :
                            key.protocol() == GpgME::OpenPGP ? i18n("OpenPGP") + QLatin1Char(',') : i18n("S/MIME") + QLatin1Char(','),
                         Kleo::Formatting::creationDateString(key));
        }
        case Qt::ToolTipRole:
            return Kleo::Formatting::toolTip(key, Kleo::Formatting::Validity |
                                                  Kleo::Formatting::Issuer |
                                                  Kleo::Formatting::Subject |
                                                  Kleo::Formatting::Fingerprint |
                                                  Kleo::Formatting::ExpiryDates |
                                                  Kleo::Formatting::UserIDs);
        case Qt::DecorationRole:
            return Kleo::Formatting::iconForUid(key.userID(0));
        default:
            return QSortFilterProxyModel::data(index, role);
        }
    }

private:
    QVector<CustomItem*> mFrontItems;
    QVector<CustomItem*> mBackItems;
};


} // anonymous namespace

namespace Kleo
{
class KeySelectionComboPrivate
{
public:
    KeySelectionComboPrivate(KeySelectionCombo *parent)
        : wasEnabled(true)
        , q(parent)
    {
    }

    /* Selects the first key with a UID addrSpec that matches
     * the mPerfectMatchMbox variable.
     *
     * The idea here is that if there are keys like:
     *
     * tom-store@abc.com
     * susi-store@abc.com
     * store@abc.com
     *
     * And the user wants to send a mail to "store@abc.com"
     * the filter should still show tom and susi (because they
     * both are part of store) but the key for "store" should
     * be preselected.
     *
     * Returns true if one was selected. False otherwise. */
    bool selectPerfectIdMatch() const
    {
        if (mPerfectMatchMbox.isEmpty()) {
            return false;
        }

        for (int i = 0; i < proxyModel->rowCount(); ++i) {
            const auto idx = proxyModel->index(i, 0, QModelIndex());
            const auto key = proxyModel->data(idx, KeyList::KeyRole).value<GpgME::Key>();
            if (key.isNull()) {
                // WTF?
                continue;
            }
            for (const auto &uid: key.userIDs()) {
                if (QString::fromStdString(uid.addrSpec()) == mPerfectMatchMbox) {
                    q->setCurrentIndex(i);
                    return true;
                }
            }
        }
        return false;
    }

    /* Updates the current key with the default key if the key matches
     * the current key filter. */
    void updateWithDefaultKey() {
        GpgME::Protocol filterProto = GpgME::UnknownProtocol;

        const auto filter = dynamic_cast<const DefaultKeyFilter*> (sortFilterProxy->keyFilter().get());
        if (filter && filter->isOpenPGP() == DefaultKeyFilter::Set) {
            filterProto = GpgME::OpenPGP;
        } else if (filter && filter->isOpenPGP() == DefaultKeyFilter::NotSet) {
            filterProto = GpgME::CMS;
        }

        QString defaultKey = defaultKeys.value (filterProto);
        if (defaultKey.isEmpty()) {
            // Fallback to unknown protocol
            defaultKey = defaultKeys.value (GpgME::UnknownProtocol);
        }
        // make sure that the default key is not filtered out unless it has the wrong protocol
        if (filterProto == GpgME::UnknownProtocol) {
            sortFilterProxy->setAlwaysAcceptedKey(defaultKey);
        } else {
            const auto key = KeyCache::instance()->findByFingerprint(defaultKey.toLatin1().constData());
            if (!key.isNull() && key.protocol() == filterProto) {
                sortFilterProxy->setAlwaysAcceptedKey(defaultKey);
            } else {
                sortFilterProxy->setAlwaysAcceptedKey({});
            }
        }
        q->setCurrentKey(defaultKey);
    }

    void storeCurrentSelectionBeforeModelChange()
    {
        keyBeforeModelChange = q->currentKey();
        customItemBeforeModelChange = q->currentData();
    }

    void restoreCurrentSelectionAfterModelChange()
    {
        if (!keyBeforeModelChange.isNull()) {
            q->setCurrentKey(keyBeforeModelChange);
        } else if (customItemBeforeModelChange.isValid()) {
            const auto index = q->findData(customItemBeforeModelChange);
            if (index != -1) {
                q->setCurrentIndex(index);
            } else {
                updateWithDefaultKey();
            }
        }
    }

    Kleo::AbstractKeyListModel *model = nullptr;
    SortFilterProxyModel *sortFilterProxy = nullptr;
    ProxyModel *proxyModel = nullptr;
    std::shared_ptr<Kleo::KeyCache> cache;
    QMap<GpgME::Protocol, QString> defaultKeys;
    bool wasEnabled = false;
    bool useWasEnabled = false;
    bool secretOnly = false;
    bool initialKeyListingDone = false;
    QString mPerfectMatchMbox;
    GpgME::Key keyBeforeModelChange;
    QVariant customItemBeforeModelChange;

private:
    KeySelectionCombo * const q;
};

}

using namespace Kleo;

KeySelectionCombo::KeySelectionCombo(QWidget* parent)
    : KeySelectionCombo(true, parent)
{}

KeySelectionCombo::KeySelectionCombo(bool secretOnly, QWidget* parent)
    : QComboBox(parent)
    , d(new KeySelectionComboPrivate(this))
{
    d->model = Kleo::AbstractKeyListModel::createFlatKeyListModel(this);
    d->secretOnly = secretOnly;

    d->sortFilterProxy = new SortFilterProxyModel(this);
    d->sortFilterProxy->setSourceModel(d->model);

    d->proxyModel = new ProxyModel(this);
    d->proxyModel->setSourceModel(d->sortFilterProxy);

    setModel(d->proxyModel);
    connect(this, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this](int row) {
                if (row >= 0 && row < d->proxyModel->rowCount()) {
                    if (d->proxyModel->isCustomItem(row)) {
                        Q_EMIT customItemSelected(currentData(Qt::UserRole));
                    } else {
                        Q_EMIT currentKeyChanged(currentKey());
                    }
                }
            });

    d->cache = Kleo::KeyCache::mutableInstance();

    connect(model(), &QAbstractItemModel::rowsAboutToBeInserted,
            this, [this] () { d->storeCurrentSelectionBeforeModelChange(); });
    connect(model(), &QAbstractItemModel::rowsInserted,
            this, [this] () { d->restoreCurrentSelectionAfterModelChange(); });
    connect(model(), &QAbstractItemModel::rowsAboutToBeRemoved,
            this, [this] () { d->storeCurrentSelectionBeforeModelChange(); });
    connect(model(), &QAbstractItemModel::rowsRemoved,
            this, [this] () { d->restoreCurrentSelectionAfterModelChange(); });
    connect(model(), &QAbstractItemModel::modelAboutToBeReset,
            this, [this] () { d->storeCurrentSelectionBeforeModelChange(); });
    connect(model(), &QAbstractItemModel::modelReset,
            this, [this] () { d->restoreCurrentSelectionAfterModelChange(); });

    QTimer::singleShot(0, this, &KeySelectionCombo::init);
}

KeySelectionCombo::~KeySelectionCombo()
{
    delete d;
}

void KeySelectionCombo::init()
{
    connect(d->cache.get(), &Kleo::KeyCache::keyListingDone,
            this, [this]() {
                    // Set useKeyCache ensures that the cache is populated
                    // so this can be a blocking call if the cache is not initialized 
                    if (!d->initialKeyListingDone) {
                        d->model->useKeyCache(true, d->secretOnly ? KeyList::SecretKeysOnly : KeyList::AllKeys);
                        d->proxyModel->removeCustomItem(QStringLiteral("-libkleo-loading-keys"));
                    }

                    // We use the useWasEnabled state variable to decide if we should
                    // change the enable / disable state based on the keylist done signal.
                    // If we triggered the refresh useWasEnabled is true and we want to
                    // enable / disable again after our refresh, as the refresh disabled it.
                    //
                    // But if a keyListingDone signal comes from just a generic refresh
                    // triggered by someone else we don't want to change the enable / disable
                    // state.
                    if (d->useWasEnabled) {
                        setEnabled(d->wasEnabled);
                        d->useWasEnabled = false;
                    }
                    Q_EMIT keyListingFinished();
            });

    connect(this, &KeySelectionCombo::keyListingFinished, this, [this]() {
            if (!d->initialKeyListingDone) {
                d->updateWithDefaultKey();
                d->initialKeyListingDone = true;
            }
        });

    if (!d->cache->initialized()) {
        refreshKeys();
    } else {
        d->model->useKeyCache(true, d->secretOnly ? KeyList::SecretKeysOnly : KeyList::AllKeys);
        Q_EMIT keyListingFinished();
    }

    connect(this, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this] () {
            setToolTip(currentData(Qt::ToolTipRole).toString());
        });
}


void KeySelectionCombo::setKeyFilter(const std::shared_ptr<const KeyFilter> &kf)
{
    d->sortFilterProxy->setKeyFilter(kf);
    d->proxyModel->sort(0);
    d->updateWithDefaultKey();
}

std::shared_ptr<const KeyFilter> KeySelectionCombo::keyFilter() const
{
    return d->sortFilterProxy->keyFilter();
}

void KeySelectionCombo::setIdFilter(const QString &id)
{
    d->sortFilterProxy->setFilterRegExp(id);
    d->mPerfectMatchMbox = id;
    d->updateWithDefaultKey();
}

QString KeySelectionCombo::idFilter() const
{
    return d->sortFilterProxy->filterRegExp().pattern();
}

GpgME::Key Kleo::KeySelectionCombo::currentKey() const
{
    return currentData(KeyList::KeyRole).value<GpgME::Key>();
}

void Kleo::KeySelectionCombo::setCurrentKey(const GpgME::Key &key)
{
    const int idx = findData(QString::fromLatin1(key.primaryFingerprint()), KeyList::FingerprintRole, Qt::MatchExactly);
    if (idx > -1) {
        setCurrentIndex(idx);
    } else if (!d->selectPerfectIdMatch()) {
        d->updateWithDefaultKey();
    }
    setToolTip(currentData(Qt::ToolTipRole).toString());
}

void Kleo::KeySelectionCombo::setCurrentKey(const QString &fingerprint)
{
    const auto cur = currentKey();
    if (!cur.isNull() && !fingerprint.isEmpty() &&
        fingerprint == QLatin1String(cur.primaryFingerprint())) {
        // already set; still emit a changed signal because the current key may
        // have become the item at the current index by changes in the underlying model
        Q_EMIT currentKeyChanged(cur);
        return;
    }
    const int idx = findData(fingerprint, KeyList::FingerprintRole, Qt::MatchExactly);
    if (idx > -1) {
        setCurrentIndex(idx);
    } else if (!d->selectPerfectIdMatch()) {
        setCurrentIndex(0);
    }
    setToolTip(currentData(Qt::ToolTipRole).toString());
}

void KeySelectionCombo::refreshKeys()
{
    d->wasEnabled = isEnabled();
    d->useWasEnabled = true;
    setEnabled(false);
    const bool wasBlocked = blockSignals(true);
    prependCustomItem(QIcon(), i18n("Loading keys ..."), QStringLiteral("-libkleo-loading-keys"));
    setCurrentIndex(0);
    blockSignals(wasBlocked);
    d->cache->startKeyListing();
}

void KeySelectionCombo::appendCustomItem(const QIcon &icon, const QString &text, const QVariant &data, const QString &toolTip)
{
    d->proxyModel->appendItem(icon, text, data, toolTip);
}

void KeySelectionCombo::appendCustomItem(const QIcon &icon, const QString &text, const QVariant &data)
{
    appendCustomItem(icon, text, data, QString());
}

void KeySelectionCombo::prependCustomItem(const QIcon &icon, const QString &text, const QVariant &data, const QString &toolTip)
{
    d->proxyModel->prependItem(icon, text, data, toolTip);
}

void KeySelectionCombo::prependCustomItem(const QIcon &icon, const QString &text, const QVariant &data)
{
    prependCustomItem(icon, text, data, QString());
}

void KeySelectionCombo::removeCustomItem(const QVariant &data)
{
    d->proxyModel->removeCustomItem(data);
}

void Kleo::KeySelectionCombo::setDefaultKey(const QString &fingerprint, GpgME::Protocol proto)
{
    d->defaultKeys.insert(proto, fingerprint);
    d->updateWithDefaultKey();
}

void Kleo::KeySelectionCombo::setDefaultKey(const QString &fingerprint)
{
    setDefaultKey(fingerprint, GpgME::UnknownProtocol);
}

QString Kleo::KeySelectionCombo::defaultKey(GpgME::Protocol proto) const
{
    return d->defaultKeys.value(proto);
}

QString Kleo::KeySelectionCombo::defaultKey() const
{
    return defaultKey(GpgME::UnknownProtocol);
}
#include "keyselectioncombo.moc"
