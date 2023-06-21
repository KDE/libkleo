/*
    keylistview.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "keylistview.h"

#include <kleo_ui_debug.h>

#include <QColor>
#include <QFont>
#include <QFontMetrics>
#include <QKeyEvent>
#include <QPoint>
#include <QTimer>
#include <QToolTip>

#include <gpgme++/key.h>

#include <map>
#include <vector>

using namespace Kleo;

static const int updateDelayMilliSecs = 500;

class Q_DECL_HIDDEN KeyListView::KeyListViewPrivate
{
public:
    KeyListViewPrivate()
        : updateTimer(nullptr)
    {
    }

    std::vector<GpgME::Key> keyBuffer;
    QTimer *updateTimer = nullptr;
    std::map<QByteArray, KeyListViewItem *> itemMap;
};

// a list of signals where we want to replace QListViewItem with
// Kleo:KeyListViewItem:
static const struct {
    const char *source;
    const char *target;
} signalReplacements[] = {
    {
        SIGNAL(itemDoubleClicked(QTreeWidgetItem *, int)),
        SLOT(slotEmitDoubleClicked(QTreeWidgetItem *, int)),
    },
    {
        SIGNAL(itemSelectionChanged()),
        SLOT(slotEmitSelectionChanged()),
    },
    {
        SIGNAL(customContextMenuRequested(QPoint)),
        SLOT(slotEmitContextMenu(QPoint)),
    },
};
static const int numSignalReplacements = sizeof signalReplacements / sizeof *signalReplacements;

KeyListView::KeyListView(const ColumnStrategy *columnStrategy, const DisplayStrategy *displayStrategy, QWidget *parent, Qt::WindowFlags f)
    : NavigatableTreeWidget(parent)
    , mColumnStrategy(columnStrategy)
    , mDisplayStrategy(displayStrategy)
    , mHierarchical(false)
    , d(new KeyListViewPrivate())
{
    setWindowFlags(f);
    setContextMenuPolicy(Qt::CustomContextMenu);

    d->updateTimer = new QTimer(this);
    d->updateTimer->setSingleShot(true);
    connect(d->updateTimer, &QTimer::timeout, this, &KeyListView::slotUpdateTimeout);
    if (!columnStrategy) {
        qCWarning(KLEO_UI_LOG) << "Kleo::KeyListView: need a column strategy to work with!";
        return;
    }

    const QFontMetrics fm = fontMetrics();

    for (int col = 0; !columnStrategy->title(col).isEmpty(); ++col) {
        headerItem()->setText(col, columnStrategy->title(col));
        header()->resizeSection(col, columnStrategy->width(col, fm));
        header()->setSectionResizeMode(col, columnStrategy->resizeMode(col));
    }

    setAllColumnsShowFocus(false);

    for (int i = 0; i < numSignalReplacements; ++i) {
        connect(this, signalReplacements[i].source, signalReplacements[i].target);
    }

    this->setToolTip(QString());
    viewport()->setToolTip(QString()); // make double sure :)
}

KeyListView::~KeyListView()
{
    d->updateTimer->stop();
    // need to clear here, since in ~QListView, our children won't have
    // a valid listView() pointing to us anymore, and their dtors try to
    // unregister from us.
    clear();
    Q_ASSERT(d->itemMap.size() == 0);
    // need to delete the tooltip ourselves, as ~QToolTip isn't virtual :o
    delete mColumnStrategy;
    mColumnStrategy = nullptr;
    delete mDisplayStrategy;
    mDisplayStrategy = nullptr;
}

void KeyListView::takeItem(QTreeWidgetItem *qlvi)
{
    // qCDebug(KLEO_UI_LOG) <<"Kleo::KeyListView::takeItem(" << qlvi <<" )";
    if (auto *item = lvi_cast<KeyListViewItem>(qlvi)) {
        deregisterItem(item);
    }
    takeTopLevelItem(indexOfTopLevelItem(qlvi));
}

void KeyListView::setHierarchical(bool hier)
{
    if (hier == mHierarchical) {
        return;
    }
    mHierarchical = hier;
    if (hier) {
        gatherScattered();
    } else {
        scatterGathered(firstChild());
    }
}

void KeyListView::slotAddKey(const GpgME::Key &key)
{
    if (key.isNull()) {
        return;
    }

    d->keyBuffer.push_back(key);
    if (!d->updateTimer->isActive()) {
        d->updateTimer->start(updateDelayMilliSecs);
    }
}

void KeyListView::slotUpdateTimeout()
{
    if (d->keyBuffer.empty()) {
        return;
    }

    const bool wasUpdatesEnabled = viewport()->updatesEnabled();
    if (wasUpdatesEnabled) {
        viewport()->setUpdatesEnabled(false);
    }
    qCDebug(KLEO_UI_LOG) << "Kleo::KeyListView::slotUpdateTimeout(): processing" << d->keyBuffer.size() << "items en block";
    if (hierarchical()) {
        for (std::vector<GpgME::Key>::const_iterator it = d->keyBuffer.begin(); it != d->keyBuffer.end(); ++it) {
            doHierarchicalInsert(*it);
        }
        gatherScattered();
    } else {
        for (std::vector<GpgME::Key>::const_iterator it = d->keyBuffer.begin(); it != d->keyBuffer.end(); ++it) {
            (void)new KeyListViewItem(this, *it);
        }
    }
    if (wasUpdatesEnabled) {
        viewport()->setUpdatesEnabled(true);
    }
    d->keyBuffer.clear();
}

void KeyListView::clear()
{
    d->updateTimer->stop();
    d->keyBuffer.clear();
    while (QTreeWidgetItem *item = topLevelItem(0)) {
        delete item;
    }
    QTreeWidget::clear();
}

void KeyListView::registerItem(KeyListViewItem *item)
{
    // qCDebug(KLEO_UI_LOG) <<"registerItem(" << item <<" )";
    if (!item) {
        return;
    }
    const QByteArray fpr = item->key().primaryFingerprint();
    if (!fpr.isEmpty()) {
        d->itemMap.insert(std::make_pair(fpr, item));
    }
}

void KeyListView::deregisterItem(const KeyListViewItem *item)
{
    // qCDebug(KLEO_UI_LOG) <<"deregisterItem( KeyLVI:" << item <<" )";
    if (!item) {
        return;
    }
    auto it = d->itemMap.find(item->key().primaryFingerprint());
    if (it == d->itemMap.end()) {
        return;
    }
    // This Q_ASSERT triggers, though it shouldn't. Print some more
    // information when it happens.
    // Q_ASSERT( it->second == item );
    if (it->second != item) {
        qCWarning(KLEO_UI_LOG) << "deregisterItem:"
                               << "item      " << item->key().primaryFingerprint() //
                               << "it->second" << (it->second ? it->second->key().primaryFingerprint() : "is null");
        return;
    }
    d->itemMap.erase(it);
}

void KeyListView::doHierarchicalInsert(const GpgME::Key &key)
{
    const QByteArray fpr = key.primaryFingerprint();
    if (fpr.isEmpty()) {
        return;
    }
    KeyListViewItem *item = nullptr;
    if (!key.isRoot()) {
        if (KeyListViewItem *parent = itemByFingerprint(key.chainID())) {
            item = new KeyListViewItem(parent, key);
            parent->setExpanded(true);
        }
    }
    if (!item) {
        item = new KeyListViewItem(this, key); // top-level (for now)
    }

    d->itemMap.insert(std::make_pair(fpr, item));
}

void KeyListView::gatherScattered()
{
    KeyListViewItem *item = firstChild();
    while (item) {
        KeyListViewItem *cur = item;
        item = item->nextSibling();
        if (cur->key().isRoot()) {
            continue;
        }
        if (KeyListViewItem *parent = itemByFingerprint(cur->key().chainID())) {
            // found a new parent...
            // ### todo: optimize by suppressing removing/adding the item to the itemMap...
            takeTopLevelItem(indexOfTopLevelItem(cur));
            parent->addChild(cur);
            parent->setExpanded(true);
        }
    }
}

void KeyListView::scatterGathered(KeyListViewItem *start)
{
    KeyListViewItem *item = start;
    while (item) {
        KeyListViewItem *cur = item;
        item = item->nextSibling();

        scatterGathered(lvi_cast<KeyListViewItem>(cur->child(0)));
        Q_ASSERT(cur->childCount() == 0);

        // ### todo: optimize by suppressing removing/adding the item to the itemMap...
        if (cur->parent()) {
            static_cast<KeyListViewItem *>(cur->parent())->takeItem(cur);
        } else {
            takeItem(cur);
        }
        addTopLevelItem(cur);
    }
}

KeyListViewItem *KeyListView::itemByFingerprint(const QByteArray &s) const
{
    if (s.isEmpty()) {
        return nullptr;
    }
    const std::map<QByteArray, KeyListViewItem *>::const_iterator it = d->itemMap.find(s);
    if (it == d->itemMap.end()) {
        return nullptr;
    }
    return it->second;
}

void KeyListView::slotRefreshKey(const GpgME::Key &key)
{
    const char *fpr = key.primaryFingerprint();
    if (!fpr) {
        return;
    }
    if (KeyListViewItem *item = itemByFingerprint(fpr)) {
        item->setKey(key);
    } else {
        // none found -> add it
        slotAddKey(key);
    }
}

// slots for the emission of covariant Q_SIGNALS:

void KeyListView::slotEmitDoubleClicked(QTreeWidgetItem *item, int col)
{
    if (!item || lvi_cast<KeyListViewItem>(item)) {
        Q_EMIT doubleClicked(static_cast<KeyListViewItem *>(item), col);
    }
}

void KeyListView::slotEmitReturnPressed(QTreeWidgetItem *item)
{
    if (!item || lvi_cast<KeyListViewItem>(item)) {
        Q_EMIT returnPressed(static_cast<KeyListViewItem *>(item));
    }
}

void KeyListView::slotEmitSelectionChanged()
{
    Q_EMIT selectionChanged(selectedItem());
}

void KeyListView::slotEmitContextMenu(const QPoint &pos)
{
    QTreeWidgetItem *item = itemAt(pos);
    if (!item || lvi_cast<KeyListViewItem>(item)) {
        Q_EMIT contextMenu(static_cast<KeyListViewItem *>(item), viewport()->mapToGlobal(pos));
    }
}

//
//
// KeyListViewItem
//
//

KeyListViewItem::KeyListViewItem(KeyListView *parent, const GpgME::Key &key)
    : QTreeWidgetItem(parent, RTTI)
{
    Q_ASSERT(parent);
    setKey(key);
}

KeyListViewItem::KeyListViewItem(KeyListView *parent, KeyListViewItem *after, const GpgME::Key &key)
    : QTreeWidgetItem(parent, after, RTTI)
{
    Q_ASSERT(parent);
    setKey(key);
}

KeyListViewItem::KeyListViewItem(KeyListViewItem *parent, const GpgME::Key &key)
    : QTreeWidgetItem(parent, RTTI)
{
    Q_ASSERT(parent && parent->listView());
    setKey(key);
}

KeyListViewItem::KeyListViewItem(KeyListViewItem *parent, KeyListViewItem *after, const GpgME::Key &key)
    : QTreeWidgetItem(parent, after, RTTI)
{
    Q_ASSERT(parent && parent->listView());
    setKey(key);
}

KeyListViewItem::~KeyListViewItem()
{
    // delete the children first... When children are deleted in the
    // QLVI dtor, they don't have listView() anymore, thus they don't
    // call deregister( this ), leading to stale entries in the
    // itemMap...
    while (QTreeWidgetItem *item = child(0)) {
        delete item;
    }
    // better do this here, too, since deletion is top-down and thus
    // we're deleted when our parent item is no longer a
    // KeyListViewItem, but a mere QListViewItem, so our takeItem()
    // overload is gone by that time...
    if (KeyListView *lv = listView()) {
        lv->deregisterItem(this);
    }
}

void KeyListViewItem::setKey(const GpgME::Key &key)
{
    KeyListView *lv = listView();
    if (lv) {
        lv->deregisterItem(this);
    }
    mKey = key;
    if (lv) {
        lv->registerItem(this);
    }

    // the ColumnStrategy operations might be very slow, so cache their
    // result here, where we're non-const :)
    const KeyListView::ColumnStrategy *cs = lv ? lv->columnStrategy() : nullptr;
    if (!cs) {
        return;
    }
    const KeyListView::DisplayStrategy *ds = lv->displayStrategy();
    const int numCols = lv ? lv->columnCount() : 0;
    for (int i = 0; i < numCols; ++i) {
        setText(i, cs->text(key, i));
        const auto accessibleText = cs->accessibleText(key, i);
        if (!accessibleText.isEmpty()) {
            setData(i, Qt::AccessibleTextRole, accessibleText);
        }
        setToolTip(i, cs->toolTip(key, i));
        const QIcon icon = cs->icon(key, i);
        if (!icon.isNull()) {
            setIcon(i, icon);
        }
        if (ds) {
            setForeground(i, QBrush(ds->keyForeground(key, foreground(i).color())));
            setBackground(i, QBrush(ds->keyBackground(key, background(i).color())));
            setFont(i, ds->keyFont(key, font(i)));
        }
    }
}

QString KeyListViewItem::toolTip(int col) const
{
    return listView() && listView()->columnStrategy() ? listView()->columnStrategy()->toolTip(key(), col) : QString();
}

bool KeyListViewItem::operator<(const QTreeWidgetItem &other) const
{
    if (other.type() != RTTI || !listView() || !listView()->columnStrategy()) {
        return QTreeWidgetItem::operator<(other);
    }
    const auto that = static_cast<const KeyListViewItem *>(&other);
    return listView()->columnStrategy()->compare(this->key(), that->key(), treeWidget()->sortColumn()) < 0;
}

void KeyListViewItem::takeItem(QTreeWidgetItem *qlvi)
{
    // qCDebug(KLEO_UI_LOG) <<"Kleo::KeyListViewItem::takeItem(" << qlvi <<" )";
    if (auto *item = lvi_cast<KeyListViewItem>(qlvi)) {
        listView()->deregisterItem(item);
    }
    takeChild(indexOfChild(qlvi));
}

//
//
// ColumnStrategy
//
//

KeyListView::ColumnStrategy::~ColumnStrategy()
{
}

int KeyListView::ColumnStrategy::compare(const GpgME::Key &key1, const GpgME::Key &key2, const int col) const
{
    return QString::localeAwareCompare(text(key1, col), text(key2, col));
}

int KeyListView::ColumnStrategy::width(int col, const QFontMetrics &fm) const
{
    return fm.horizontalAdvance(title(col)) * 2;
}

QString KeyListView::ColumnStrategy::toolTip(const GpgME::Key &key, int col) const
{
    return text(key, col);
}

//
//
// DisplayStrategy
//
//

KeyListView::DisplayStrategy::~DisplayStrategy()
{
}

// font
QFont KeyListView::DisplayStrategy::keyFont(const GpgME::Key &, const QFont &font) const
{
    return font;
}

// foreground
QColor KeyListView::DisplayStrategy::keyForeground(const GpgME::Key &, const QColor &fg) const
{
    return fg;
}

// background
QColor KeyListView::DisplayStrategy::keyBackground(const GpgME::Key &, const QColor &bg) const
{
    return bg;
}

//
//
// Collection of covariant return reimplementations of QListView(Item)
// members:
//
//

KeyListView *KeyListViewItem::listView() const
{
    return static_cast<KeyListView *>(QTreeWidgetItem::treeWidget());
}

KeyListViewItem *KeyListViewItem::nextSibling() const
{
    if (parent()) {
        const int myIndex = parent()->indexOfChild(const_cast<KeyListViewItem *>(this));
        return static_cast<KeyListViewItem *>(parent()->child(myIndex + 1));
    }
    const int myIndex = treeWidget()->indexOfTopLevelItem(const_cast<KeyListViewItem *>(this));
    return static_cast<KeyListViewItem *>(treeWidget()->topLevelItem(myIndex + 1));
}

KeyListViewItem *KeyListView::firstChild() const
{
    return static_cast<KeyListViewItem *>(topLevelItem(0));
}

KeyListViewItem *KeyListView::selectedItem() const
{
    QList<KeyListViewItem *> selection = selectedItems();
    if (selection.isEmpty()) {
        return nullptr;
    }
    return selection.first();
}

QList<KeyListViewItem *> KeyListView::selectedItems() const
{
    QList<KeyListViewItem *> result;
    const auto selectedItems = QTreeWidget::selectedItems();
    for (QTreeWidgetItem *selectedItem : selectedItems) {
        if (auto *i = lvi_cast<KeyListViewItem>(selectedItem)) {
            result.append(i);
        }
    }
    return result;
}

bool KeyListView::isMultiSelection() const
{
    return selectionMode() == ExtendedSelection || selectionMode() == MultiSelection;
}

void KeyListView::keyPressEvent(QKeyEvent *event)
{
    if (event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter) {
        if (selectedItem()) {
            slotEmitReturnPressed(selectedItem());
        }
    }
    QTreeView::keyPressEvent(event);
}

#include "moc_keylistview.cpp"
