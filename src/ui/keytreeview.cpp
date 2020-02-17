/*  ui/keytreeview.cpp

    This file is part of Kleopatra, the KDE keymanager
    Copyright (c) 2009 Klarälvdalens Datakonsult AB
    Copyright (c) 2020 g10 Code GmbH

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

#include "keytreeview.h"
#include "headerview.h"

#include "models/keylistmodel.h"
#include "models/keylistsortfilterproxymodel.h"
#include "models/keyrearrangecolumnsproxymodel.h"
#include "models/keycache.h"

#include "kleo/predicates.h"
#include "kleo/remarks.h"
#include "kleo/stl_util.h"
#include "kleo/keyfilter.h"

#include <gpgme++/key.h>

#include "libkleo_debug.h"
#include <QTimer>
#include <QTreeView>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QItemSelection>
#include <QLayout>
#include <QList>
#include <QMenu>
#include <QAction>
#include <QEvent>
#include <QContextMenuEvent>

#include <KSharedConfig>
#include <KConfigGroup>
#include <KLocalizedString>

#include <gpgme++/gpgmepp_version.h>
#if GPGMEPP_VERSION >= 0x10E00 // 1.14.0
# define GPGME_HAS_REMARKS
#endif

#define REMARK_COLUMN 13

using namespace Kleo;
using namespace GpgME;

Q_DECLARE_METATYPE(GpgME::Key)

namespace
{

class TreeView : public QTreeView
{
public:
    explicit TreeView(QWidget *parent = nullptr) : QTreeView(parent)
    {
        header()->installEventFilter(this);
    }

    QSize minimumSizeHint() const override
    {
        const QSize min = QTreeView::minimumSizeHint();
        return QSize(min.width(), min.height() + 5 * fontMetrics().height());
    }

protected:
    bool eventFilter(QObject *watched, QEvent *event) override
    {
        Q_UNUSED(watched);
        if (event->type() == QEvent::ContextMenu) {
            QContextMenuEvent *e = static_cast<QContextMenuEvent *>(event);

            if (!mHeaderPopup) {
                mHeaderPopup = new QMenu(this);
                mHeaderPopup->setTitle(i18n("View Columns"));
                for (int i = 0; i < model()->columnCount(); ++i) {
                    QAction *tmp
                        = mHeaderPopup->addAction(model()->headerData(i, Qt::Horizontal).toString());
                    tmp->setData(QVariant(i));
                    tmp->setCheckable(true);
                    mColumnActions << tmp;
                }

                connect(mHeaderPopup, &QMenu::triggered, this, [this] (QAction *action) {
                    const int col = action->data().toInt();
                    if (col == REMARK_COLUMN) {
                        Remarks::enableRemarks(action->isChecked());
                    }
                    if (action->isChecked()) {
                        showColumn(col);
                    } else {
                        hideColumn(col);
                    }

                    KeyTreeView *tv = qobject_cast<KeyTreeView *> (parent());
                    if (tv) {
                        tv->resizeColumns();
                    }
                });
            }

            foreach (QAction *action, mColumnActions) {
                int column = action->data().toInt();
                action->setChecked(!isColumnHidden(column));
            }

            mHeaderPopup->popup(mapToGlobal(e->pos()));
            return true;
        }

        return false;
    }

private:
    QMenu *mHeaderPopup = nullptr;

    QList<QAction *> mColumnActions;
};

} // anon namespace

KeyTreeView::KeyTreeView(QWidget *parent)
    : QWidget(parent),
      m_proxy(new KeyListSortFilterProxyModel(this)),
      m_additionalProxy(nullptr),
      m_view(new TreeView(this)),
      m_flatModel(nullptr),
      m_hierarchicalModel(nullptr),
      m_stringFilter(),
      m_keyFilter(),
      m_isHierarchical(true)
{
    init();
}

KeyTreeView::KeyTreeView(const KeyTreeView &other)
    : QWidget(nullptr),
      m_proxy(new KeyListSortFilterProxyModel(this)),
      m_additionalProxy(other.m_additionalProxy ? other.m_additionalProxy->clone() : nullptr),
      m_view(new TreeView(this)),
      m_flatModel(other.m_flatModel),
      m_hierarchicalModel(other.m_hierarchicalModel),
      m_stringFilter(other.m_stringFilter),
      m_keyFilter(other.m_keyFilter),
      m_group(other.m_group),
      m_isHierarchical(other.m_isHierarchical)
{
    init();
    setColumnSizes(other.columnSizes());
    setSortColumn(other.sortColumn(), other.sortOrder());
}

KeyTreeView::KeyTreeView(const QString &text, const std::shared_ptr<KeyFilter> &kf,
                         AbstractKeyListSortFilterProxyModel *proxy, QWidget *parent,
                         const KConfigGroup &group)
    : QWidget(parent),
      m_proxy(new KeyListSortFilterProxyModel(this)),
      m_additionalProxy(proxy),
      m_view(new TreeView(this)),
      m_flatModel(nullptr),
      m_hierarchicalModel(nullptr),
      m_stringFilter(text),
      m_keyFilter(kf),
      m_group(group),
      m_isHierarchical(true),
      m_onceResized(false)
{
    init();
}

void KeyTreeView::setColumnSizes(const std::vector<int> &sizes)
{
    if (sizes.empty()) {
        return;
    }
    Q_ASSERT(m_view);
    Q_ASSERT(m_view->header());
    Q_ASSERT(qobject_cast<HeaderView *>(m_view->header()) == static_cast<HeaderView *>(m_view->header()));
    if (HeaderView *const hv = static_cast<HeaderView *>(m_view->header())) {
        hv->setSectionSizes(sizes);
    }
}

void KeyTreeView::setSortColumn(int sortColumn, Qt::SortOrder sortOrder)
{
    Q_ASSERT(m_view);
    m_view->sortByColumn(sortColumn, sortOrder);
}

int KeyTreeView::sortColumn() const
{
    Q_ASSERT(m_view);
    Q_ASSERT(m_view->header());
    return m_view->header()->sortIndicatorSection();
}

Qt::SortOrder KeyTreeView::sortOrder() const
{
    Q_ASSERT(m_view);
    Q_ASSERT(m_view->header());
    return m_view->header()->sortIndicatorOrder();
}

std::vector<int> KeyTreeView::columnSizes() const
{
    Q_ASSERT(m_view);
    Q_ASSERT(m_view->header());
    Q_ASSERT(qobject_cast<HeaderView *>(m_view->header()) == static_cast<HeaderView *>(m_view->header()));
    if (HeaderView *const hv = static_cast<HeaderView *>(m_view->header())) {
        return hv->sectionSizes();
    } else {
        return std::vector<int>();
    }
}

void KeyTreeView::init()
{
    if (!m_group.isValid()) {
        m_group = KSharedConfig::openConfig()->group("KeyTreeView_default");
    } else {
        // Reopen as non const
        KConfig *conf = m_group.config();
        m_group = conf->group(m_group.name());
    }

    QLayout *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(m_view);

    HeaderView *headerView = new HeaderView(Qt::Horizontal);
    headerView->installEventFilter(m_view);
    headerView->setSectionsMovable(true);
    m_view->setHeader(headerView);

    m_view->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_view->setSelectionMode(QAbstractItemView::ExtendedSelection);
    //m_view->setAlternatingRowColors( true );
    m_view->setAllColumnsShowFocus(true);
    m_view->setSortingEnabled(true);

    if (model()) {
        if (m_additionalProxy) {
            m_additionalProxy->setSourceModel(model());
        } else {
            m_proxy->setSourceModel(model());
        }
    }
    if (m_additionalProxy) {
        m_proxy->setSourceModel(m_additionalProxy);
        if (!m_additionalProxy->parent()) {
            m_additionalProxy->setParent(this);
        }
    }

    m_proxy->setFilterFixedString(m_stringFilter);
    m_proxy->setKeyFilter(m_keyFilter);
    m_proxy->setSortCaseSensitivity(Qt::CaseInsensitive);

    KeyRearrangeColumnsProxyModel *rearangingModel = new KeyRearrangeColumnsProxyModel(this);
    rearangingModel->setSourceModel(m_proxy);
    rearangingModel->setSourceColumns(QVector<int>() << KeyListModelInterface::PrettyName
                                                     << KeyListModelInterface::PrettyEMail
                                                     << KeyListModelInterface::Validity
                                                     << KeyListModelInterface::ValidFrom
                                                     << KeyListModelInterface::ValidUntil
                                                     << KeyListModelInterface::TechnicalDetails
                                                     << KeyListModelInterface::KeyID
                                                     << KeyListModelInterface::Fingerprint
                                                     << KeyListModelInterface::OwnerTrust
                                                     << KeyListModelInterface::Origin
                                                     << KeyListModelInterface::LastUpdate
                                                     << KeyListModelInterface::Issuer
                                                     << KeyListModelInterface::SerialNumber
#ifdef GPGME_HAS_REMARKS
    // If a column is added before this REMARK_COLUMN define has to be updated accordingly
                                                     << KeyListModelInterface::Remarks
#endif
    );
    m_view->setModel(rearangingModel);

    /* Handle expansion state */
    m_expandedKeys = m_group.readEntry("Expanded", QStringList());

    connect(m_view, &QTreeView::expanded, this, [this] (const QModelIndex &index) {
        if (!index.isValid()) {
            return;
        }
        const auto &key = index.data(Kleo::KeyListModelInterface::KeyRole).value<GpgME::Key>();
        const auto fpr = QString::fromLatin1(key.primaryFingerprint());

        if (m_expandedKeys.contains(fpr)) {
            return;
        }
        m_expandedKeys << fpr;
        m_group.writeEntry("Expanded", m_expandedKeys);
    });

    connect(m_view, &QTreeView::collapsed, this, [this] (const QModelIndex &index) {
        if (!index.isValid()) {
            return;
        }
        const auto &key = index.data(Kleo::KeyListModelInterface::KeyRole).value<GpgME::Key>();
        m_expandedKeys.removeAll(QString::fromLatin1(key.primaryFingerprint()));
        m_group.writeEntry("Expanded", m_expandedKeys);
    });

    connect(KeyCache::instance().get(), &KeyCache::keysMayHaveChanged, this, [this] () {
        /* We use a single shot timer here to ensure that the keysMayHaveChanged
         * handlers are all handled before we restore the expand state so that
         * the model is already populated. */
        QTimer::singleShot(0, [this] () {
            restoreExpandState();
            setupRemarkKeys();
            if (!m_onceResized) {
                m_onceResized = true;
                resizeColumns();
            }
        });
    });
    resizeColumns();
    restoreLayout();
}

void KeyTreeView::restoreExpandState()
{
    if (!KeyCache::instance()->initialized()) {
        qCWarning(LIBKLEO_LOG) << "Restore expand state before keycache available. Aborting.";
        return;
    }
    for (const auto &fpr: m_expandedKeys) {
        const KeyListModelInterface *km = dynamic_cast<const KeyListModelInterface*> (m_view->model());
        if (!km) {
            qCWarning(LIBKLEO_LOG) << "invalid model";
            return;
        }
        const auto key = KeyCache::instance()->findByFingerprint(fpr.toLatin1().constData());
        if (key.isNull()) {
            qCDebug(LIBKLEO_LOG) << "Cannot find:" << fpr << "anymore in cache";
            m_expandedKeys.removeAll(fpr);
            return;
        }
        const auto idx = km->index(key);
        if (!idx.isValid()) {
            qCDebug(LIBKLEO_LOG) << "Cannot find:" << fpr << "anymore in model";
            m_expandedKeys.removeAll(fpr);
            return;
        }
        m_view->expand(idx);
    }
}

void KeyTreeView::setupRemarkKeys()
{
#ifdef GPGME_HAS_REMARKS
    const auto remarkKeys = Remarks::remarkKeys();
    if (m_hierarchicalModel) {
        m_hierarchicalModel->setRemarkKeys(remarkKeys);
    }
    if (m_flatModel) {
        m_flatModel->setRemarkKeys(remarkKeys);
    }
#endif
}

void KeyTreeView::saveLayout()
{
    QHeaderView *header = m_view->header();

    QVariantList columnVisibility;
    QVariantList columnOrder;
    QVariantList columnWidths;
    const int headerCount = header->count();
    columnVisibility.reserve(headerCount);
    columnWidths.reserve(headerCount);
    columnOrder.reserve(headerCount);
    for (int i = 0; i < headerCount; ++i) {
        columnVisibility << QVariant(!m_view->isColumnHidden(i));
        columnWidths << QVariant(header->sectionSize(i));
        columnOrder << QVariant(header->visualIndex(i));
    }

    m_group.writeEntry("ColumnVisibility", columnVisibility);
    m_group.writeEntry("ColumnOrder", columnOrder);
    m_group.writeEntry("ColumnWidths", columnWidths);

    m_group.writeEntry("SortAscending", (int)header->sortIndicatorOrder());
    if (header->isSortIndicatorShown()) {
        m_group.writeEntry("SortColumn", header->sortIndicatorSection());
    } else {
        m_group.writeEntry("SortColumn", -1);
    }
}

void KeyTreeView::restoreLayout()
{
    QHeaderView *header = m_view->header();

    QVariantList columnVisibility = m_group.readEntry("ColumnVisibility", QVariantList());
    QVariantList columnOrder = m_group.readEntry("ColumnOrder", QVariantList());
    QVariantList columnWidths = m_group.readEntry("ColumnWidths", QVariantList());

    if (columnVisibility.isEmpty()) {
        // if config is empty then use default settings
        // The numbers have to be in line with the order in
        // setsSourceColumns above
        m_view->hideColumn(5);

        for (int i = 7; i < m_view->model()->columnCount(); ++i) {
            m_view->hideColumn(i);
        }
        if (KeyCache::instance()->initialized()) {
            QTimer::singleShot(0, this, &KeyTreeView::resizeColumns);
        }
    } else {
        for (int i = 0; i < header->count(); ++i) {
            if (i >= columnOrder.size() || i >= columnWidths.size() || i >= columnVisibility.size()) {
                // An additional column that was not around last time we saved.
                // We default to hidden.
                m_view->hideColumn(i);
                continue;
            }
            bool visible = columnVisibility[i].toBool();
            int width = columnWidths[i].toInt();
            int order = columnOrder[i].toInt();

            header->resizeSection(i, width ? width : 100);
            header->moveSection(header->visualIndex(i), order);
            if (i == REMARK_COLUMN) {
                Remarks::enableRemarks(visible);
            }
            if (!visible) {
                m_view->hideColumn(i);
            }
        }
        m_onceResized = true;
    }

    int sortOrder = m_group.readEntry("SortAscending", (int)Qt::AscendingOrder);
    int sortColumn = m_group.readEntry("SortColumn", -1);
    if (sortColumn >= 0) {
        m_view->sortByColumn(sortColumn, (Qt::SortOrder)sortOrder);
    }
}

KeyTreeView::~KeyTreeView()
{
    saveLayout();
}

static QAbstractProxyModel *find_last_proxy(QAbstractProxyModel *pm)
{
    Q_ASSERT(pm);
    while (QAbstractProxyModel *const sm = qobject_cast<QAbstractProxyModel *>(pm->sourceModel())) {
        pm = sm;
    }
    return pm;
}

void KeyTreeView::setFlatModel(AbstractKeyListModel *model)
{
    if (model == m_flatModel) {
        return;
    }
    m_flatModel = model;
    if (!m_isHierarchical)
        // TODO: this fails when called after setHierarchicalView( false )...
    {
        find_last_proxy(m_proxy)->setSourceModel(model);
    }
}

void KeyTreeView::setHierarchicalModel(AbstractKeyListModel *model)
{
    if (model == m_hierarchicalModel) {
        return;
    }
    m_hierarchicalModel = model;
    if (m_isHierarchical) {
        find_last_proxy(m_proxy)->setSourceModel(model);
        m_view->expandAll();
        for (int column = 0; column < m_view->header()->count(); ++column) {
            m_view->header()->resizeSection(column, qMax(m_view->header()->sectionSize(column), m_view->header()->sectionSizeHint(column)));
        }
    }
}

void KeyTreeView::setStringFilter(const QString &filter)
{
    if (filter == m_stringFilter) {
        return;
    }
    m_stringFilter = filter;
    m_proxy->setFilterFixedString(filter);
    Q_EMIT stringFilterChanged(filter);
}

void KeyTreeView::setKeyFilter(const std::shared_ptr<KeyFilter> &filter)
{
    if (filter == m_keyFilter || (filter && m_keyFilter && filter->id() == m_keyFilter->id())) {
        return;
    }
    m_keyFilter = filter;
    m_proxy->setKeyFilter(filter);
    Q_EMIT keyFilterChanged(filter);
}

static QItemSelection itemSelectionFromKeys(const std::vector<Key> &keys, const KeyListSortFilterProxyModel &proxy)
{
    QItemSelection result;
    for (const Key &key : keys) {
        const QModelIndex mi = proxy.index(key);
        if (mi.isValid()) {
            result.merge(QItemSelection(mi, mi), QItemSelectionModel::Select);
        }
    }
    return result;
}

void KeyTreeView::selectKeys(const std::vector<Key> &keys)
{
    m_view->selectionModel()->select(itemSelectionFromKeys(keys, *m_proxy), QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
}

std::vector<Key> KeyTreeView::selectedKeys() const
{
    return m_proxy->keys(m_view->selectionModel()->selectedRows());
}

void KeyTreeView::setHierarchicalView(bool on)
{
    if (on == m_isHierarchical) {
        return;
    }
    if (on && !hierarchicalModel()) {
        qCWarning(LIBKLEO_LOG) <<  "hierarchical view requested, but no hierarchical model set";
        return;
    }
    if (!on && !flatModel()) {
        qCWarning(LIBKLEO_LOG) << "flat view requested, but no flat model set";
        return;
    }
    const std::vector<Key> selectedKeys = m_proxy->keys(m_view->selectionModel()->selectedRows());
    const Key currentKey = m_proxy->key(m_view->currentIndex());

    m_isHierarchical = on;
    find_last_proxy(m_proxy)->setSourceModel(model());
    if (on) {
        m_view->expandAll();
    }
    selectKeys(selectedKeys);
    if (!currentKey.isNull()) {
        const QModelIndex currentIndex = m_proxy->index(currentKey);
        if (currentIndex.isValid()) {
            m_view->selectionModel()->setCurrentIndex(m_proxy->index(currentKey), QItemSelectionModel::NoUpdate);
            m_view->scrollTo(currentIndex);
        }
    }
    Q_EMIT hierarchicalChanged(on);
}

void KeyTreeView::setKeys(const std::vector<Key> &keys)
{
    std::vector<Key> sorted = keys;
    _detail::sort_by_fpr(sorted);
    _detail::remove_duplicates_by_fpr(sorted);
    m_keys = sorted;
    if (m_flatModel) {
        m_flatModel->setKeys(sorted);
    }
    if (m_hierarchicalModel) {
        m_hierarchicalModel->setKeys(sorted);
    }
}

void KeyTreeView::addKeysImpl(const std::vector<Key> &keys, bool select)
{
    if (keys.empty()) {
        return;
    }
    if (m_keys.empty()) {
        setKeys(keys);
        return;
    }

    std::vector<Key> sorted = keys;
    _detail::sort_by_fpr(sorted);
    _detail::remove_duplicates_by_fpr(sorted);

    std::vector<Key> newKeys = _detail::union_by_fpr(sorted, m_keys);
    m_keys.swap(newKeys);

    if (m_flatModel) {
        m_flatModel->addKeys(sorted);
    }
    if (m_hierarchicalModel) {
        m_hierarchicalModel->addKeys(sorted);
    }

    if (select) {
        selectKeys(sorted);
    }
}

void KeyTreeView::addKeysSelected(const std::vector<Key> &keys)
{
    addKeysImpl(keys, true);
}

void KeyTreeView::addKeysUnselected(const std::vector<Key> &keys)
{
    addKeysImpl(keys, false);
}

void KeyTreeView::removeKeys(const std::vector<Key> &keys)
{
    if (keys.empty()) {
        return;
    }
    std::vector<Key> sorted = keys;
    _detail::sort_by_fpr(sorted);
    _detail::remove_duplicates_by_fpr(sorted);
    std::vector<Key> newKeys;
    newKeys.reserve(m_keys.size());
    std::set_difference(m_keys.begin(), m_keys.end(),
                        sorted.begin(), sorted.end(),
                        std::back_inserter(newKeys),
                        _detail::ByFingerprint<std::less>());
    m_keys.swap(newKeys);

    if (m_flatModel) {
        std::for_each(sorted.cbegin(), sorted.cend(),
                      [this](const Key &key) { m_flatModel->removeKey(key); });
    }
    if (m_hierarchicalModel) {
        std::for_each(sorted.cbegin(), sorted.cend(),
                      [this](const Key &key) { m_hierarchicalModel->removeKey(key); });
    }

}

static const struct {
    const char *signal;
    const char *slot;
} connections[] = {
    {
        SIGNAL(stringFilterChanged(QString)),
        SLOT(setStringFilter(QString))
    },
    {
        SIGNAL(keyFilterChanged(std::shared_ptr<Kleo::KeyFilter>)),
        SLOT(setKeyFilter(std::shared_ptr<Kleo::KeyFilter>))
    },
};
static const unsigned int numConnections = sizeof connections / sizeof * connections;

void KeyTreeView::disconnectSearchBar(const QObject *bar)
{
    for (unsigned int i = 0; i < numConnections; ++i) {
        disconnect(this, connections[i].signal, bar,  connections[i].slot);
        disconnect(bar,  connections[i].signal, this, connections[i].slot);
    }
}

bool KeyTreeView::connectSearchBar(const QObject *bar)
{
    for (unsigned int i = 0; i < numConnections; ++i)
        if (!connect(this, connections[i].signal, bar,  connections[i].slot) ||
                !connect(bar,  connections[i].signal, this, connections[i].slot)) {
            return false;
        }
    return true;
}

void KeyTreeView::resizeColumns()
{
    m_view->setColumnWidth(KeyListModelInterface::PrettyName, 260);
    m_view->setColumnWidth(KeyListModelInterface::PrettyEMail, 260);

    for (int i = 2; i < m_view->model()->columnCount(); ++i) {
        m_view->resizeColumnToContents(i);
    }
}
