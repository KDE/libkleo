/*  This file is part of Kleopatra, the KDE keymanager
    Copyright (c) 2016 Klarälvdalens Datakonsult AB

    Kleopatra is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kleopatra is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "keyselectioncombo.h"
#include <kleo_ui_debug.h>

#include "kleo/dn.h"
#include "models/keylistmodel.h"
#include "models/keylistsortfilterproxymodel.h"
#include "models/keycache.h"
#include "utils/formatting.h"
#include "progressbar.h"

#include <gpgme++/key.h>

#include <QSortFilterProxyModel>
#include <QVector>
#include <QTimer>

#include <KLocalizedString>

Q_DECLARE_METATYPE(GpgME::Key)

namespace
{

class ProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

private:
    struct CustomItem {
        QIcon icon;
        QString text;
        QVariant data;
    };
public:
    ProxyModel(QObject *parent = nullptr)
        : QSortFilterProxyModel(parent)
    {
    }

    ~ProxyModel()
    {
        qDeleteAll(mFrontItems);
        qDeleteAll(mBackItems);
    }

    bool isCustomItem(const int row) const
    {
        return row < mFrontItems.count() || row >= mFrontItems.count() + QSortFilterProxyModel::rowCount();
    }

    void prependItem(const QIcon &icon, const QString &text, const QVariant &data)
    {
        beginInsertRows(QModelIndex(), 0, 0);
        mFrontItems.push_front(new CustomItem{ icon, text, data });
        endInsertRows();
    }

    void appendItem(const QIcon &icon, const QString &text, const QVariant &data)
    {
        beginInsertRows(QModelIndex(), rowCount(), rowCount());
        mBackItems.push_back(new CustomItem{ icon, text, data });
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
            const QModelIndex idx = createIndex(row, index.column(), index.internalPointer());
            return QSortFilterProxyModel::mapToSource(idx);
        } else {
            return QModelIndex();
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
            return QModelIndex();
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
        Q_UNUSED(index);
        return Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemNeverHasChildren;
    }

    QModelIndex parent(const QModelIndex &) const override
    {
        // Flat list
        return QModelIndex();
    }

    QVariant data(const QModelIndex &index, int role) const override
    {
        if (!index.isValid()) {
            return QVariant();
        }

        if (isCustomItem(index.row())) {
            Q_ASSERT(!mFrontItems.isEmpty() || !mBackItems.isEmpty());
            CustomItem *ci = static_cast<CustomItem*>(index.internalPointer());
            switch (role) {
            case Qt::DisplayRole:
                return ci->text;
            case Qt::DecorationRole:
                return ci->icon;
            case Qt::UserRole:
                return ci->data;
            default:
                return QVariant();
            }
        }

        const auto key = QSortFilterProxyModel::data(index, Kleo::KeyListModelInterface::KeyRole).value<GpgME::Key>();
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
            return i18nc("Name <email> (validity, type, created: date)", "%1 (%2, %3, created: %4)",
                         email.isEmpty() ? name : name.isEmpty() ? email : i18nc("Name <email>", "%1 <%2>", name, email),
                         Kleo::Formatting::complianceStringShort(key),
                         key.protocol() == GpgME::OpenPGP ? i18n("OpenPGP") : i18n("S/MIME"),
                         Kleo::Formatting::creationDateString(key));
        }
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

    Kleo::AbstractKeyListModel *model = nullptr;
    Kleo::KeyListSortFilterProxyModel *sortFilterProxy = nullptr;
    ProxyModel *proxyModel = nullptr;
    std::shared_ptr<Kleo::KeyCache> cache;
    QString defaultKey;
    bool wasEnabled = false;

private:
    KeySelectionCombo * const q;
};

}

using namespace Kleo;


KeySelectionCombo::KeySelectionCombo(QWidget* parent)
    : QComboBox(parent)
    , d(new KeySelectionComboPrivate(this))
{
    d->model = Kleo::AbstractKeyListModel::createFlatKeyListModel(this);

    d->sortFilterProxy = new Kleo::KeyListSortFilterProxyModel(this);
    d->sortFilterProxy->setSourceModel(d->model);

    d->proxyModel = new ProxyModel(this);
    d->proxyModel->setSourceModel(d->sortFilterProxy);

    setModel(d->proxyModel);
    connect(this, static_cast<void(KeySelectionCombo::*)(int)>(&KeySelectionCombo::currentIndexChanged),
            this, [this](int row) {
                if (row >= 0 && row < d->proxyModel->rowCount()) {
                    if (d->proxyModel->isCustomItem(row)) {
                        Q_EMIT customItemSelected(d->proxyModel->index(row, 0).data(Qt::UserRole));
                    } else {
                        Q_EMIT currentKeyChanged(currentKey());
                    }
                }
            });

    d->cache = Kleo::KeyCache::mutableInstance();

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
                    // so this can be a blocking call if the cache is not initalized 
                    qDebug() << "Key listing done"; 
                    d->model->useKeyCache(true, true);
                    d->proxyModel->removeCustomItem(QStringLiteral("-libkleo-loading-keys"));
                    setEnabled(d->wasEnabled);
                    Q_EMIT keyListingFinished(); 
            });

    connect(this, &KeySelectionCombo::keyListingFinished, this, [this]() { setCurrentKey(d->defaultKey); });

    if (!d->cache->initialized()) {
        refreshKeys();
    } else {
        d->model->useKeyCache(true, true);
        Q_EMIT keyListingFinished();
    }
}


void KeySelectionCombo::setKeyFilter(const std::shared_ptr<const KeyFilter> &kf)
{
    d->sortFilterProxy->setKeyFilter(kf);
    setCurrentKey(d->defaultKey);
}

std::shared_ptr<const KeyFilter> KeySelectionCombo::keyFilter() const
{
    return d->sortFilterProxy->keyFilter();
}

void KeySelectionCombo::setIdFilter(const QString &id)
{
    d->sortFilterProxy->setFilterRegExp(id);
    setCurrentKey(d->defaultKey);
}

QString KeySelectionCombo::idFilter() const
{
    return d->sortFilterProxy->filterRegExp().pattern();
}

GpgME::Key Kleo::KeySelectionCombo::currentKey() const
{
    return currentData(Kleo::KeyListModelInterface::KeyRole).value<GpgME::Key>();
}

void Kleo::KeySelectionCombo::setCurrentKey(const GpgME::Key &key)
{
    const int idx = findData(QVariant::fromValue(key), Kleo::KeyListModelInterface::KeyRole, Qt::MatchExactly);
    if (idx > -1) {
        setCurrentIndex(idx);
    }
}

void Kleo::KeySelectionCombo::setCurrentKey(const QString &fingerprint)
{
    for (int i = 0; i < d->proxyModel->rowCount(); ++i) {
        const auto idx = d->proxyModel->index(i, 0, QModelIndex());
        const auto key = d->proxyModel->data(idx, Kleo::KeyListModelInterface::KeyRole).value<GpgME::Key>();
        if (!key.isNull() && fingerprint == QString::fromLatin1(key.primaryFingerprint())) {
            setCurrentIndex(i);
            return;
        }
    }
    setCurrentIndex(0);
}

void KeySelectionCombo::refreshKeys()
{
    d->wasEnabled = isEnabled();
    setEnabled(false);
    const bool wasBlocked = blockSignals(true);
    prependCustomItem(QIcon(), i18n("Loading keys ..."), QStringLiteral("-libkleo-loading-keys"));
    setCurrentIndex(0);
    blockSignals(wasBlocked);
    d->cache->startKeyListing();
}

void KeySelectionCombo::appendCustomItem(const QIcon &icon, const QString &text, const QVariant &data)
{
    d->proxyModel->appendItem(icon, text, data);
}

void KeySelectionCombo::prependCustomItem(const QIcon &icon, const QString &text, const QVariant &data)
{
    d->proxyModel->prependItem(icon, text, data);
}

void Kleo::KeySelectionCombo::setDefaultKey(const QString &fingerprint)
{
    d->defaultKey = fingerprint;
}

QString Kleo::KeySelectionCombo::defaultKey() const
{
    return d->defaultKey;
}

#include "keyselectioncombo.moc"
