/*  This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "useridselectioncombo.h"

#include "progressbar.h"

#include <libkleo/defaultkeyfilter.h>
#include <libkleo/dn.h>
#include <libkleo/formatting.h>
#include <libkleo/keycache.h>
#include <libkleo/keyfiltermanager.h>
#include <libkleo/keyhelpers.h>
#include <libkleo/keylist.h>
#include <libkleo/keylistmodel.h>
#include <libkleo/keylistsortfilterproxymodel.h>
#include <libkleo/useridproxymodel.h>

#include <kleo_ui_debug.h>

#include <KLocalizedString>

#include <QHBoxLayout>
#include <QList>
#include <QSortFilterProxyModel>
#include <QTimer>
#include <QToolButton>

#include <gpgme++/key.h>

using namespace Kleo;

Q_DECLARE_METATYPE(GpgME::Key)
Q_DECLARE_METATYPE(GpgME::UserID)

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

static QString formatUserID(const GpgME::UserID &userID)
{
    QString name;
    QString email;

    if (userID.parent().protocol() == GpgME::OpenPGP) {
        name = QString::fromUtf8(userID.name());
        email = QString::fromUtf8(userID.email());
    } else {
        const Kleo::DN dn(userID.id());
        name = dn[QStringLiteral("CN")];
        email = dn[QStringLiteral("EMAIL")];
        if (name.isEmpty()) {
            name = Kleo::DN(userID.parent().userID(0).id())[QStringLiteral("CN")];
        }
    }
    return email.isEmpty() ? name : name.isEmpty() ? email : i18nc("Name <email>", "%1 <%2>", name, email);
}

class SortAndFormatCertificatesProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    SortAndFormatCertificatesProxyModel(KeyUsage::Flags usageFlags, QObject *parent = nullptr)
        : QSortFilterProxyModel{parent}
        , mIconProvider{usageFlags}
    {
    }

private:
    bool lessThan(const QModelIndex &left, const QModelIndex &right) const override
    {
        const auto leftUserId = sourceModel()->data(left, KeyList::UserIDRole).value<GpgME::UserID>();
        const auto rightUserId = sourceModel()->data(right, KeyList::UserIDRole).value<GpgME::UserID>();
        if (leftUserId.isNull()) {
            return false;
        }
        if (rightUserId.isNull()) {
            return true;
        }
        const auto leftNameAndEmail = formatUserID(leftUserId);
        const auto rightNameAndEmail = formatUserID(rightUserId);
        const int cmp = QString::localeAwareCompare(leftNameAndEmail, rightNameAndEmail);
        if (cmp) {
            return cmp < 0;
        }

        if (leftUserId.validity() != rightUserId.validity()) {
            return leftUserId.validity() > rightUserId.validity();
        }

        /* Both have the same validity, check which one is newer. */
        time_t leftTime = 0;
        for (const GpgME::Subkey &s : leftUserId.parent().subkeys()) {
            if (s.isBad()) {
                continue;
            }
            if (s.creationTime() > leftTime) {
                leftTime = s.creationTime();
            }
        }
        time_t rightTime = 0;
        for (const GpgME::Subkey &s : rightUserId.parent().subkeys()) {
            if (s.isBad()) {
                continue;
            }
            if (s.creationTime() > rightTime) {
                rightTime = s.creationTime();
            }
        }
        if (rightTime != leftTime) {
            return leftTime > rightTime;
        }

        // as final resort we compare the fingerprints
        return strcmp(leftUserId.parent().primaryFingerprint(), rightUserId.parent().primaryFingerprint()) < 0;
    }

protected:
    QVariant data(const QModelIndex &index, int role) const override
    {
        if (!index.isValid()) {
            return QVariant();
        }

        const auto userId = QSortFilterProxyModel::data(index, KeyList::UserIDRole).value<GpgME::UserID>();
        Q_ASSERT(!userId.isNull());
        if (userId.isNull()) {
            return QVariant();
        }

        switch (role) {
        case Qt::DisplayRole:
        case Qt::AccessibleTextRole: {
            const auto nameAndEmail = formatUserID(userId);
            if (Kleo::KeyCache::instance()->pgpOnly()) {
                return i18nc("Name <email> (validity, created: date)",
                             "%1 (%2, created: %3)",
                             nameAndEmail,
                             Kleo::Formatting::complianceStringShort(userId),
                             Kleo::Formatting::creationDateString(userId.parent()));
            } else {
                return i18nc("Name <email> (validity, type, created: date)",
                             "%1 (%2, %3, created: %4)",
                             nameAndEmail,
                             Kleo::Formatting::complianceStringShort(userId),
                             Formatting::displayName(userId.parent().protocol()),
                             Kleo::Formatting::creationDateString(userId.parent()));
            }
        }
        case Qt::ToolTipRole: {
            using namespace Kleo::Formatting;
            return Kleo::Formatting::toolTip(userId, Validity | Issuer | Subject | Fingerprint | ExpiryDates | UserIDs);
        }
        case Qt::DecorationRole: {
            return mIconProvider.icon(userId.parent());
        }
        case Qt::FontRole: {
            return KeyFilterManager::instance()->font(userId.parent(), QFont());
        }
        default:
            return QSortFilterProxyModel::data(index, role);
        }
    }

private:
    Formatting::IconProvider mIconProvider;
};

class CustomItemsProxyModel : public QSortFilterProxyModel
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
    CustomItemsProxyModel(QObject *parent = nullptr)
        : QSortFilterProxyModel(parent)
    {
    }

    ~CustomItemsProxyModel() override
    {
        qDeleteAll(mFrontItems);
        qDeleteAll(mBackItems);
    }

    bool isCustomItem(const int row) const
    {
        return row < mFrontItems.count() || row >= mFrontItems.count() + QSortFilterProxyModel::rowCount();
    }

    void prependItem(const QIcon &icon, const QString &text, const QVariant &data, const QString &toolTip)
    {
        beginInsertRows(QModelIndex(), 0, 0);
        mFrontItems.push_front(new CustomItem{icon, text, data, toolTip});
        endInsertRows();
    }

    void appendItem(const QIcon &icon, const QString &text, const QVariant &data, const QString &toolTip)
    {
        beginInsertRows(QModelIndex(), rowCount(), rowCount());
        mBackItems.push_back(new CustomItem{icon, text, data, toolTip});
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

    int columnCount(const QModelIndex &parent = QModelIndex()) const override
    {
        Q_UNUSED(parent)
        // pretend that there is only one column to workaround a bug in
        // QAccessibleTable which provides the accessibility interface for the
        // pop-up of the combo box
        return 1;
    }

    QModelIndex mapToSource(const QModelIndex &index) const override
    {
        if (!index.isValid()) {
            return {};
        }
        if (!isCustomItem(index.row())) {
            const int sourceRow = index.row() - mFrontItems.count();
            return QSortFilterProxyModel::mapToSource(createIndex(sourceRow, index.column(), index.internalPointer()));
        }
        return {};
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
            auto ci = static_cast<CustomItem *>(index.internalPointer());
            switch (role) {
            case Qt::DisplayRole:
                return ci->text;
            case Qt::DecorationRole:
                return ci->icon;
            case Qt::UserRole:
            case KeyList::UserIDRole:
                return ci->data;
            case Qt::ToolTipRole:
                return ci->toolTip;
            default:
                return QVariant();
            }
        }

        return QSortFilterProxyModel::data(index, role);
    }

private:
    QList<CustomItem *> mFrontItems;
    QList<CustomItem *> mBackItems;
};

} // anonymous namespace

namespace Kleo
{
class UserIDSelectionComboPrivate
{
public:
    UserIDSelectionComboPrivate(UserIDSelectionCombo *parent, bool secretOnly_, KeyUsage::Flags usage)
        : wasEnabled(true)
        , secretOnly{secretOnly_}
        , usageFlags{usage}
        , q{parent}
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
            const auto userID = idx.data(KeyList::UserIDRole).value<GpgME::UserID>();
            if (userID.isNull()) {
                // WTF?
                continue;
            }
            if (QString::fromStdString(userID.addrSpec()) == mPerfectMatchMbox) {
                combo->setCurrentIndex(i);
                return true;
            }
        }
        return false;
    }

    /* Updates the current key with the default key if the key matches
     * the current key filter. */
    void updateWithDefaultKey()
    {
        GpgME::Protocol filterProto = GpgME::UnknownProtocol;

        const auto filter = dynamic_cast<const DefaultKeyFilter *>(sortFilterProxy->keyFilter().get());
        if (filter && filter->isOpenPGP() == DefaultKeyFilter::Set) {
            filterProto = GpgME::OpenPGP;
        } else if (filter && filter->isOpenPGP() == DefaultKeyFilter::NotSet) {
            filterProto = GpgME::CMS;
        }

        QString defaultKey = defaultKeys.value(filterProto);
        if (defaultKey.isEmpty()) {
            // Fallback to unknown protocol
            defaultKey = defaultKeys.value(GpgME::UnknownProtocol);
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
        userIDBeforeModelChange = q->currentUserID();
        customItemBeforeModelChange = combo->currentData();
    }

    void restoreCurrentSelectionAfterModelChange()
    {
        if (!userIDBeforeModelChange.isNull()) {
            q->setCurrentUserID(userIDBeforeModelChange);
        } else if (customItemBeforeModelChange.isValid()) {
            const auto index = combo->findData(customItemBeforeModelChange);
            if (index != -1) {
                combo->setCurrentIndex(index);
            } else {
                updateWithDefaultKey();
            }
        }
    }

    Kleo::AbstractKeyListModel *model = nullptr;
    UserIDProxyModel *userIdProxy = nullptr;
    SortFilterProxyModel *sortFilterProxy = nullptr;
    SortAndFormatCertificatesProxyModel *sortAndFormatProxy = nullptr;
    CustomItemsProxyModel *proxyModel = nullptr;
    QComboBox *combo = nullptr;
    QToolButton *button = nullptr;
    std::shared_ptr<Kleo::KeyCache> cache;
    QMap<GpgME::Protocol, QString> defaultKeys;
    bool wasEnabled = false;
    bool useWasEnabled = false;
    bool secretOnly = false;
    bool initialKeyListingDone = false;
    QString mPerfectMatchMbox;
    GpgME::UserID userIDBeforeModelChange;
    QVariant customItemBeforeModelChange;
    KeyUsage::Flags usageFlags;

private:
    UserIDSelectionCombo *const q;
};

}

using namespace Kleo;

UserIDSelectionCombo::UserIDSelectionCombo(QWidget *parent)
    : UserIDSelectionCombo(true, KeyUsage::None, parent)
{
}

UserIDSelectionCombo::UserIDSelectionCombo(bool secretOnly, QWidget *parent)
    : UserIDSelectionCombo(secretOnly, KeyUsage::None, parent)
{
}

UserIDSelectionCombo::UserIDSelectionCombo(KeyUsage::Flags usage, QWidget *parent)
    : UserIDSelectionCombo{false, usage, parent}
{
}

UserIDSelectionCombo::UserIDSelectionCombo(KeyUsage::Flag usage, QWidget *parent)
    : UserIDSelectionCombo{false, usage, parent}
{
}

UserIDSelectionCombo::UserIDSelectionCombo(bool secretOnly, KeyUsage::Flags usage, QWidget *parent)
    : QWidget(parent)
    , d(new UserIDSelectionComboPrivate(this, secretOnly, usage))
{
    // set a non-empty string as accessible description to prevent screen readers
    // from reading the tool tip which isn't meant for screen readers
    setAccessibleDescription(QStringLiteral(" "));
    d->model = Kleo::AbstractKeyListModel::createFlatKeyListModel(this);

    d->userIdProxy = new UserIDProxyModel(this);
    d->userIdProxy->setSourceModel(d->model);

    d->sortFilterProxy = new SortFilterProxyModel(this);
    d->sortFilterProxy->setSourceModel(d->userIdProxy);

    d->sortAndFormatProxy = new SortAndFormatCertificatesProxyModel{usage, this};
    d->sortAndFormatProxy->setSourceModel(d->sortFilterProxy);
    // initialize dynamic sorting
    d->sortAndFormatProxy->sort(0);

    d->proxyModel = new CustomItemsProxyModel{this};
    d->proxyModel->setSourceModel(d->sortAndFormatProxy);

    auto layout = new QHBoxLayout(this);
    layout->setContentsMargins({});

    d->combo = new QComboBox(parent);
    layout->addWidget(d->combo);

    d->button = new QToolButton(parent);
    d->button->setIcon(QIcon::fromTheme(QStringLiteral("resource-group-new")));
    d->button->setToolTip(i18nc("@info:tooltip", "Show certificate list"));
    d->button->setAccessibleName(i18n("Show certificate list"));
    layout->addWidget(d->button);

    connect(d->button, &QToolButton::clicked, this, &UserIDSelectionCombo::certificateSelectionRequested);

    d->combo->setModel(d->proxyModel);
    connect(d->combo, &QComboBox::currentIndexChanged, this, [this](int row) {
        if (row >= 0 && row < d->proxyModel->rowCount()) {
            if (d->proxyModel->isCustomItem(row)) {
                Q_EMIT customItemSelected(d->combo->currentData(Qt::UserRole));
            } else {
                Q_EMIT currentKeyChanged(currentKey());
            }
        }
    });

    d->cache = Kleo::KeyCache::mutableInstance();

    connect(d->combo->model(), &QAbstractItemModel::rowsAboutToBeInserted, this, [this]() {
        d->storeCurrentSelectionBeforeModelChange();
    });
    connect(d->combo->model(), &QAbstractItemModel::rowsInserted, this, [this]() {
        d->restoreCurrentSelectionAfterModelChange();
    });
    connect(d->combo->model(), &QAbstractItemModel::rowsAboutToBeRemoved, this, [this]() {
        d->storeCurrentSelectionBeforeModelChange();
    });
    connect(d->combo->model(), &QAbstractItemModel::rowsRemoved, this, [this]() {
        d->restoreCurrentSelectionAfterModelChange();
    });
    connect(d->combo->model(), &QAbstractItemModel::modelAboutToBeReset, this, [this]() {
        d->storeCurrentSelectionBeforeModelChange();
    });
    connect(d->combo->model(), &QAbstractItemModel::modelReset, this, [this]() {
        d->restoreCurrentSelectionAfterModelChange();
    });

    QTimer::singleShot(0, this, &UserIDSelectionCombo::init);
}

UserIDSelectionCombo::~UserIDSelectionCombo() = default;

void UserIDSelectionCombo::init()
{
    connect(d->cache.get(), &Kleo::KeyCache::keyListingDone, this, [this]() {
        // Set useKeyCache ensures that the cache is populated
        // so this can be a blocking call if the cache is not initialized
        if (!d->initialKeyListingDone) {
            d->model->useKeyCache(true, d->secretOnly ? KeyList::SecretKeysOnly : KeyList::AllKeys);
        }
        d->proxyModel->removeCustomItem(QStringLiteral("-libkleo-loading-keys"));

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

    connect(this, &UserIDSelectionCombo::keyListingFinished, this, [this]() {
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

    connect(d->combo, &QComboBox::currentIndexChanged, this, [this]() {
        setToolTip(d->combo->currentData(Qt::ToolTipRole).toString());
    });
}

void UserIDSelectionCombo::setKeyFilter(const std::shared_ptr<const KeyFilter> &kf)
{
    d->sortFilterProxy->setKeyFilter(kf);
    d->updateWithDefaultKey();
}

std::shared_ptr<const KeyFilter> UserIDSelectionCombo::keyFilter() const
{
    return d->sortFilterProxy->keyFilter();
}

void UserIDSelectionCombo::setIdFilter(const QString &id)
{
    d->sortFilterProxy->setFilterRegularExpression(id);
    d->mPerfectMatchMbox = id;
    d->updateWithDefaultKey();
}

QString UserIDSelectionCombo::idFilter() const
{
    return d->sortFilterProxy->filterRegularExpression().pattern();
}

GpgME::Key Kleo::UserIDSelectionCombo::currentKey() const
{
    return d->combo->currentData(KeyList::KeyRole).value<GpgME::Key>();
}

void Kleo::UserIDSelectionCombo::setCurrentKey(const GpgME::Key &key)
{
    const int idx = d->combo->findData(QString::fromLatin1(key.primaryFingerprint()), KeyList::FingerprintRole, Qt::MatchExactly);
    if (idx > -1) {
        d->combo->setCurrentIndex(idx);
    } else if (!d->selectPerfectIdMatch()) {
        d->updateWithDefaultKey();
    }
    setToolTip(d->combo->currentData(Qt::ToolTipRole).toString());
}

void Kleo::UserIDSelectionCombo::setCurrentKey(const QString &fingerprint)
{
    const auto cur = currentKey();
    if (!cur.isNull() && !fingerprint.isEmpty() && fingerprint == QLatin1String(cur.primaryFingerprint())) {
        // already set; still emit a changed signal because the current key may
        // have become the item at the current index by changes in the underlying model
        Q_EMIT currentKeyChanged(cur);
        return;
    }
    const int idx = d->combo->findData(fingerprint, KeyList::FingerprintRole, Qt::MatchExactly);
    if (idx > -1) {
        d->combo->setCurrentIndex(idx);
    } else if (!d->selectPerfectIdMatch()) {
        d->combo->setCurrentIndex(0);
    }
    setToolTip(d->combo->currentData(Qt::ToolTipRole).toString());
}

GpgME::UserID Kleo::UserIDSelectionCombo::currentUserID() const
{
    return d->combo->currentData(KeyList::UserIDRole).value<GpgME::UserID>();
}

void Kleo::UserIDSelectionCombo::setCurrentUserID(const GpgME::UserID &userID)
{
    for (auto i = 0; i < d->combo->count(); i++) {
        const auto &other = d->combo->itemData(i, KeyList::UserIDRole).value<GpgME::UserID>();
        if (!qstrcmp(userID.id(), other.id()) && !qstrcmp(userID.parent().primaryFingerprint(), other.parent().primaryFingerprint())) {
            d->combo->setCurrentIndex(i);
            setToolTip(d->combo->currentData(Qt::ToolTipRole).toString());
            return;
        }
    }
    if (!d->selectPerfectIdMatch()) {
        d->updateWithDefaultKey();
        setToolTip(d->combo->currentData(Qt::ToolTipRole).toString());
    }
}

void UserIDSelectionCombo::refreshKeys()
{
    d->wasEnabled = isEnabled();
    d->useWasEnabled = true;
    setEnabled(false);
    const bool wasBlocked = blockSignals(true);
    prependCustomItem(QIcon(), i18n("Loading keys ..."), QStringLiteral("-libkleo-loading-keys"));
    d->combo->setCurrentIndex(0);
    blockSignals(wasBlocked);
    d->cache->startKeyListing();
}

void UserIDSelectionCombo::appendCustomItem(const QIcon &icon, const QString &text, const QVariant &data, const QString &toolTip)
{
    d->proxyModel->appendItem(icon, text, data, toolTip);
}

void UserIDSelectionCombo::appendCustomItem(const QIcon &icon, const QString &text, const QVariant &data)
{
    appendCustomItem(icon, text, data, QString());
}

void UserIDSelectionCombo::prependCustomItem(const QIcon &icon, const QString &text, const QVariant &data, const QString &toolTip)
{
    d->proxyModel->prependItem(icon, text, data, toolTip);
}

void UserIDSelectionCombo::prependCustomItem(const QIcon &icon, const QString &text, const QVariant &data)
{
    prependCustomItem(icon, text, data, QString());
}

void UserIDSelectionCombo::removeCustomItem(const QVariant &data)
{
    d->proxyModel->removeCustomItem(data);
}

void Kleo::UserIDSelectionCombo::setDefaultKey(const QString &fingerprint, GpgME::Protocol proto)
{
    d->defaultKeys.insert(proto, fingerprint);
    d->updateWithDefaultKey();
}

void Kleo::UserIDSelectionCombo::setDefaultKey(const QString &fingerprint)
{
    setDefaultKey(fingerprint, GpgME::UnknownProtocol);
}

QString Kleo::UserIDSelectionCombo::defaultKey(GpgME::Protocol proto) const
{
    return d->defaultKeys.value(proto);
}

QString Kleo::UserIDSelectionCombo::defaultKey() const
{
    return defaultKey(GpgME::UnknownProtocol);
}

QComboBox *Kleo::UserIDSelectionCombo::combo() const
{
    return d->combo;
}

int Kleo::UserIDSelectionCombo::findUserId(const GpgME::UserID &userId) const
{
    for (int i = 0; i < combo()->model()->rowCount(); i++) {
        if (Kleo::userIDsAreEqual(userId, combo()->model()->index(i, 0).data(KeyList::UserIDRole).value<GpgME::UserID>())) {
            return i;
        }
    }
    return -1;
}

#include "useridselectioncombo.moc"

#include "moc_useridselectioncombo.cpp"
