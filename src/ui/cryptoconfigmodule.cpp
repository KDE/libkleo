/*
    cryptoconfigmodule.cpp

    This file is part of kgpgcertmanager
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "cryptoconfigmodule.h"

#include "cryptoconfigentryreaderport_p.h"
#include "cryptoconfigmodule_p.h"
#include "directoryserviceswidget.h"
#include "filenamerequester.h"

#include <libkleo/compliance.h>
#include <libkleo/formatting.h>
#include <libkleo/gnupg.h>
#include <libkleo/keyserverconfig.h>

#include <kleo_ui_debug.h>

#include <KLazyLocalizedString>
#include <KLineEdit>
#include <KLocalizedString>
#include <KMessageBox>
#include <KSeparator>

#include <QGpgME/CryptoConfig>

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLayout>
#include <QPushButton>
#include <QRegularExpression>
#include <QScreen>
#include <QScrollArea>
#include <QSpinBox>
#include <QStyle>
#include <QVBoxLayout>

#include <gpgme.h>

#include <array>
#include <limits>
#include <memory>
#include <set>

using namespace Kleo;

namespace
{

class ScrollArea : public QScrollArea
{
public:
    explicit ScrollArea(QWidget *p)
        : QScrollArea(p)
    {
    }
    QSize sizeHint() const override
    {
        const QSize wsz = widget() ? widget()->sizeHint() : QSize();
        return {wsz.width() + style()->pixelMetric(QStyle::PM_ScrollBarExtent), QScrollArea::sizeHint().height()};
    }
};

}
inline QIcon loadIcon(const QString &s)
{
    QString ss = s;
    const static QRegularExpression reg(QRegularExpression(QLatin1String("[^a-zA-Z0-9_]")));
    return QIcon::fromTheme(ss.replace(reg, QStringLiteral("-")));
}

static unsigned int num_components_with_options(const QGpgME::CryptoConfig *config)
{
    if (!config) {
        return 0;
    }
    const QStringList components = config->componentList();
    unsigned int result = 0;
    for (QStringList::const_iterator it = components.begin(); it != components.end(); ++it) {
        if (const QGpgME::CryptoConfigComponent *const comp = config->component(*it)) {
            if (!comp->groupList().empty()) {
                ++result;
            }
        }
    }
    return result;
}

static KPageView::FaceType determineJanusFace(const QGpgME::CryptoConfig *config, Kleo::CryptoConfigModule::Layout layout, bool &ok)
{
    ok = true;
    if (num_components_with_options(config) < 2) {
        ok = false;
        return KPageView::Plain;
    }
    switch (layout) {
    case CryptoConfigModule::LinearizedLayout:
        return KPageView::Plain;
    case CryptoConfigModule::TabbedLayout:
        return KPageView::Tabbed;
    case CryptoConfigModule::IconListLayout:
        return KPageView::List;
    }
    Q_ASSERT(!"we should never get here");
    return KPageView::List;
}

Kleo::CryptoConfigModule::CryptoConfigModule(QGpgME::CryptoConfig *config, QWidget *parent)
    : KPageWidget(parent)
    , mConfig(config)
{
    init(IconListLayout);
}

Kleo::CryptoConfigModule::CryptoConfigModule(QGpgME::CryptoConfig *config, Layout layout, QWidget *parent)
    : KPageWidget(parent)
    , mConfig(config)
{
    init(layout);
}

void Kleo::CryptoConfigModule::init(Layout layout)
{
    if (QLayout *l = this->layout()) {
        l->setContentsMargins(0, 0, 0, 0);
    }

    QGpgME::CryptoConfig *const config = mConfig;

    bool configOK = false;
    const KPageView::FaceType type = determineJanusFace(config, layout, configOK);

    setFaceType(type);

    QVBoxLayout *vlay = nullptr;
    QWidget *vbox = nullptr;

    if (type == Plain) {
        QWidget *w = new QWidget(this);
        auto l = new QVBoxLayout(w);
        l->setContentsMargins(0, 0, 0, 0);
        auto s = new QScrollArea(w);
        s->setFrameStyle(QFrame::NoFrame);
        s->setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Preferred);
        s->setWidgetResizable(true);
        l->addWidget(s);
        vbox = new QWidget(s->viewport());
        vlay = new QVBoxLayout(vbox);
        vlay->setContentsMargins(0, 0, 0, 0);
        s->setWidget(vbox);
        addPage(w, configOK ? QString() : i18n("GpgConf Error"));
    }

    const QStringList components = sortComponentList(config->componentList());
    for (QStringList::const_iterator it = components.begin(); it != components.end(); ++it) {
        // qCDebug(KLEO_UI_LOG) <<"Component" << (*it).toLocal8Bit() <<":";
        QGpgME::CryptoConfigComponent *comp = config->component(*it);
        Q_ASSERT(comp);
        if (comp->groupList().empty()) {
            continue;
        }

        std::unique_ptr<CryptoConfigComponentGUI> compGUI(new CryptoConfigComponentGUI(this, comp));
        compGUI->setObjectName(*it);
        // KJanusWidget doesn't seem to have iterators, so we store a copy...
        mComponentGUIs.append(compGUI.get());

        if (type == Plain) {
            QGroupBox *gb = new QGroupBox(comp->description(), vbox);
            (new QVBoxLayout(gb))->addWidget(compGUI.release());
            vlay->addWidget(gb);
        } else {
            vbox = new QWidget(this);
            vlay = new QVBoxLayout(vbox);
            vlay->setContentsMargins(0, 0, 0, 0);
            KPageWidgetItem *pageItem = new KPageWidgetItem(vbox, comp->description());
            if (type != Tabbed) {
                pageItem->setIcon(loadIcon(comp->iconName()));
            }
            addPage(pageItem);

            QScrollArea *scrollArea = type == Tabbed ? new QScrollArea(vbox) : new ScrollArea(vbox);
            scrollArea->setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Preferred);
            scrollArea->setWidgetResizable(true);

            vlay->addWidget(scrollArea);
            const QSize compGUISize = compGUI->sizeHint();
            scrollArea->setWidget(compGUI.release());

            // Set a nice startup size
            const int deskHeight = screen()->size().height();
            int dialogHeight;
            if (deskHeight > 1000) { // very big desktop ?
                dialogHeight = 800;
            } else if (deskHeight > 650) { // big desktop ?
                dialogHeight = 500;
            } else { // small (800x600, 640x480) desktop
                dialogHeight = 400;
            }
            Q_ASSERT(scrollArea->widget());
            if (type != Tabbed) {
                scrollArea->setMinimumHeight(qMin(compGUISize.height(), dialogHeight));
            }
        }
    }
    if (mComponentGUIs.empty()) {
        const QString msg = i18n(
            "The gpgconf tool used to provide the information "
            "for this dialog does not seem to be installed "
            "properly. It did not return any components. "
            "Try running \"%1\" on the command line for more "
            "information.",
            components.empty() ? QLatin1String("gpgconf --list-components") : QLatin1String("gpgconf --list-options gpg"));
        QLabel *label = new QLabel(msg, vbox);
        label->setWordWrap(true);
        label->setMinimumHeight(fontMetrics().lineSpacing() * 5);
        vlay->addWidget(label);
    }
}

namespace
{
template<typename Iterator>
QStringList sortConfigEntries(const Iterator orderBegin, const Iterator orderEnd, const QStringList &entries)
{
    // components sorting algorithm:
    // 1. components with predefined order (provided via orderBegin / orderEnd)
    // 2. other components sorted alphabetically
    QStringList result;
    QStringList others;
    for (auto it = orderBegin; it != orderEnd; ++it) {
        if (entries.contains(*it)) {
            result.append(*it);
        }
    }
    for (const auto &item : entries) {
        if (!result.contains(item)) {
            others.append(item);
        }
    }
    others.sort();
    result.append(others);
    return result;
}
} // namespace

QStringList Kleo::CryptoConfigModule::sortComponentList(const QStringList &components)
{
    static const std::array<QString, 6> order = {
        QStringLiteral("gpg"),
        QStringLiteral("gpgsm"),
        QStringLiteral("gpg-agent"),
        QStringLiteral("dirmngr"),
        QStringLiteral("pinentry"),
        QStringLiteral("scdaemon"),
    };
    return sortConfigEntries(order.begin(), order.end(), components);
}

QStringList Kleo::CryptoConfigModule::sortGroupList(const QString &moduleName, const QStringList &groups)
{
    if (moduleName == QStringLiteral("gpg")) {
        static const std::array<QString, 4> order = {
            QStringLiteral("Keyserver"),
            QStringLiteral("Configuration"),
            QStringLiteral("Monitor"),
            QStringLiteral("Debug"),
        };
        return sortConfigEntries(order.begin(), order.end(), groups);
    } else if (moduleName == QStringLiteral("gpgsm")) {
        static const std::array<QString, 4> order = {
            QStringLiteral("Security"),
            QStringLiteral("Configuration"),
            QStringLiteral("Monitor"),
            QStringLiteral("Debug"),
        };
        return sortConfigEntries(order.begin(), order.end(), groups);
    } else if (moduleName == QStringLiteral("gpg-agent")) {
        static const std::array<QString, 5> order = {
            QStringLiteral("Security"),
            QStringLiteral("Passphrase policy"),
            QStringLiteral("Configuration"),
            QStringLiteral("Monitor"),
            QStringLiteral("Debug"),
        };
        return sortConfigEntries(order.begin(), order.end(), groups);
    } else if (moduleName == QStringLiteral("dirmngr")) {
        static const std::array<QString, 10> order = {
            QStringLiteral("Keyserver"),
            QStringLiteral("HTTP"),
            QStringLiteral("LDAP"),
            QStringLiteral("OCSP"),
            QStringLiteral("Tor"),
            QStringLiteral("Enforcement"),
            QStringLiteral("Configuration"),
            QStringLiteral("Format"),
            QStringLiteral("Monitor"),
            QStringLiteral("Debug"),
        };
        return sortConfigEntries(order.begin(), order.end(), groups);
    } else if (moduleName == QStringLiteral("scdaemon")) {
        static const std::array<QString, 4> order = {
            QStringLiteral("Monitor"),
            QStringLiteral("Configuration"),
            QStringLiteral("Security"),
            QStringLiteral("Debug"),
        };
        return sortConfigEntries(order.begin(), order.end(), groups);
    } else {
        qCDebug(KLEO_UI_LOG) << "Configuration groups order is not defined for " << moduleName;
        QStringList result(groups);
        result.sort();
        return result;
    }
}

bool Kleo::CryptoConfigModule::hasError() const
{
    return mComponentGUIs.empty();
}

void Kleo::CryptoConfigModule::save()
{
    bool changed = false;
    QList<CryptoConfigComponentGUI *>::Iterator it = mComponentGUIs.begin();
    for (; it != mComponentGUIs.end(); ++it) {
        if ((*it)->save()) {
            changed = true;
        }
    }
    if (changed) {
        mConfig->sync(true /*runtime*/);
    }
}

void Kleo::CryptoConfigModule::reset()
{
    QList<CryptoConfigComponentGUI *>::Iterator it = mComponentGUIs.begin();
    for (; it != mComponentGUIs.end(); ++it) {
        (*it)->load();
    }
}

void Kleo::CryptoConfigModule::defaults()
{
    QList<CryptoConfigComponentGUI *>::Iterator it = mComponentGUIs.begin();
    for (; it != mComponentGUIs.end(); ++it) {
        (*it)->defaults();
    }
}

void Kleo::CryptoConfigModule::cancel()
{
    mConfig->clear();
}

////

namespace
{
bool offerEntryForConfiguration(QGpgME::CryptoConfigEntry *entry)
{
    static const QRegularExpression entryPathGroupSegmentRegexp{QStringLiteral("/.*/")};

    static std::set<QString> entriesToExclude;
    if (entriesToExclude.empty()) {
        entriesToExclude.insert(QStringLiteral("gpg/keyserver"));
        if (engineIsVersion(2, 3, 5, GpgME::GpgConfEngine)
            || (engineIsVersion(2, 2, 34, GpgME::GpgConfEngine) && !engineIsVersion(2, 3, 0, GpgME::GpgConfEngine))) {
            // exclude for 2.2.{34,...} and 2.3.5+
            entriesToExclude.insert(QStringLiteral("gpgsm/keyserver"));
        }
    }

    const bool de_vs = DeVSCompliance::isActive();
    // Skip "dangerous" expert options if we are running in CO_DE_VS.
    // Otherwise, skip any options beyond "invisible" (== expert + 1) level.
    const auto maxEntryLevel = de_vs ? QGpgME::CryptoConfigEntry::Level_Advanced //
                                     : QGpgME::CryptoConfigEntry::Level_Expert + 1;
    // we ignore the group when looking up entries to exclude because entries
    // are uniquely identified by their name and their component
    const auto entryId = entry->path().replace(entryPathGroupSegmentRegexp, QLatin1String{"/"}).toLower();
    return (entry->level() <= maxEntryLevel) && (entriesToExclude.find(entryId) == entriesToExclude.end());
}

auto getGroupEntriesToOfferForConfiguration(QGpgME::CryptoConfigGroup *group)
{
    std::vector<QGpgME::CryptoConfigEntry *> result;
    const auto entryNames = group->entryList();
    for (const auto &entryName : entryNames) {
        auto *const entry = group->entry(entryName);
        Q_ASSERT(entry);
        if (offerEntryForConfiguration(entry)) {
            result.push_back(entry);
        } else {
            qCDebug(KLEO_UI_LOG) << "entry" << entry->path() << "too advanced or excluded explicitly, skipping";
        }
    }
    return result;
}
}

Kleo::CryptoConfigComponentGUI::CryptoConfigComponentGUI(CryptoConfigModule *module, QGpgME::CryptoConfigComponent *component, QWidget *parent)
    : QWidget(parent)
    , mComponent(component)
{
    auto glay = new QGridLayout(this);
    const QStringList groups = module->sortGroupList(mComponent->name(), mComponent->groupList());
    if (groups.size() > 1) {
        glay->setColumnMinimumWidth(0, 30);
        for (QStringList::const_iterator it = groups.begin(), end = groups.end(); it != end; ++it) {
            QGpgME::CryptoConfigGroup *group = mComponent->group(*it);
            Q_ASSERT(group);
            if (!group) {
                continue;
            }
            auto groupEntries = getGroupEntriesToOfferForConfiguration(group);
            if (groupEntries.size() == 0) {
                // skip groups without entries to be offered in the UI
                continue;
            }
            const QString title = group->description();
            auto hbox = new QHBoxLayout;
            hbox->addWidget(new QLabel{title.isEmpty() ? *it : title, this});
            hbox->addWidget(new KSeparator{Qt::Horizontal, this}, 1);
            const int row = glay->rowCount();
            glay->addLayout(hbox, row, 0, 1, 3);
            mGroupGUIs.append(new CryptoConfigGroupGUI(module, group, groupEntries, glay, this));
        }
    } else if (!groups.empty()) {
        auto *const group = mComponent->group(groups.front());
        auto groupEntries = getGroupEntriesToOfferForConfiguration(group);
        if (groupEntries.size() > 0) {
            mGroupGUIs.append(new CryptoConfigGroupGUI(module, group, groupEntries, glay, this));
        }
    }
    glay->setRowStretch(glay->rowCount(), 1);
}

bool Kleo::CryptoConfigComponentGUI::save()
{
    bool changed = false;
    QList<CryptoConfigGroupGUI *>::Iterator it = mGroupGUIs.begin();
    for (; it != mGroupGUIs.end(); ++it) {
        if ((*it)->save()) {
            changed = true;
        }
    }
    return changed;
}

void Kleo::CryptoConfigComponentGUI::load()
{
    QList<CryptoConfigGroupGUI *>::Iterator it = mGroupGUIs.begin();
    for (; it != mGroupGUIs.end(); ++it) {
        (*it)->load();
    }
}

void Kleo::CryptoConfigComponentGUI::defaults()
{
    QList<CryptoConfigGroupGUI *>::Iterator it = mGroupGUIs.begin();
    for (; it != mGroupGUIs.end(); ++it) {
        (*it)->defaults();
    }
}

////

Kleo::CryptoConfigGroupGUI::CryptoConfigGroupGUI(CryptoConfigModule *module,
                                                 QGpgME::CryptoConfigGroup *group,
                                                 const std::vector<QGpgME::CryptoConfigEntry *> &entries,
                                                 QGridLayout *glay,
                                                 QWidget *widget)
    : QObject(module)
{
    const int startRow = glay->rowCount();
    for (auto entry : entries) {
        CryptoConfigEntryGUI *entryGUI = CryptoConfigEntryGUIFactory::createEntryGUI(module, entry, entry->name(), glay, widget);
        if (entryGUI) {
            mEntryGUIs.append(entryGUI);
            entryGUI->load();
        }
    }
    const int endRow = glay->rowCount() - 1;
    if (endRow < startRow) {
        return;
    }

    const QString iconName = group->iconName();
    if (iconName.isEmpty()) {
        return;
    }

    QLabel *l = new QLabel(widget);
    l->setPixmap(loadIcon(iconName).pixmap(32, 32));
    glay->addWidget(l, startRow, 0, endRow - startRow + 1, 1, Qt::AlignTop);
}

bool Kleo::CryptoConfigGroupGUI::save()
{
    bool changed = false;
    QList<CryptoConfigEntryGUI *>::Iterator it = mEntryGUIs.begin();
    for (; it != mEntryGUIs.end(); ++it) {
        if ((*it)->isChanged()) {
            (*it)->save();
            changed = true;
        }
    }
    return changed;
}

void Kleo::CryptoConfigGroupGUI::load()
{
    QList<CryptoConfigEntryGUI *>::Iterator it = mEntryGUIs.begin();
    for (; it != mEntryGUIs.end(); ++it) {
        (*it)->load();
    }
}

void Kleo::CryptoConfigGroupGUI::defaults()
{
    QList<CryptoConfigEntryGUI *>::Iterator it = mEntryGUIs.begin();
    for (; it != mEntryGUIs.end(); ++it) {
        (*it)->resetToDefault();
    }
}

////

using constructor = CryptoConfigEntryGUI *(*)(CryptoConfigModule *, QGpgME::CryptoConfigEntry *, const QString &, QGridLayout *, QWidget *);

namespace
{
template<typename T_Widget>
CryptoConfigEntryGUI *_create(CryptoConfigModule *m, QGpgME::CryptoConfigEntry *e, const QString &n, QGridLayout *l, QWidget *p)
{
    return new T_Widget(m, e, n, l, p);
}
}

static const struct WidgetsByEntryName {
    const char *entryGlob;
    constructor create;
} widgetsByEntryName[] = {
    {"*/*/debug-level", &_create<CryptoConfigEntryDebugLevel>},
    {"scdaemon/*/reader-port", &_create<CryptoConfigEntryReaderPort>},
};
static const unsigned int numWidgetsByEntryName = sizeof widgetsByEntryName / sizeof *widgetsByEntryName;

static const constructor listWidgets[QGpgME::CryptoConfigEntry::NumArgType] = {
    // None: A list of options with no arguments (e.g. -v -v -v) is shown as a spinbox
    &_create<CryptoConfigEntrySpinBox>,
    nullptr, // String
    // Int/UInt: Let people type list of numbers (1,2,3....). Untested.
    &_create<CryptoConfigEntryLineEdit>,
    &_create<CryptoConfigEntryLineEdit>,
    nullptr, // Path
    nullptr, // Formerly URL
    &_create<CryptoConfigEntryLDAPURL>,
    nullptr, // DirPath
};

static const constructor scalarWidgets[QGpgME::CryptoConfigEntry::NumArgType] = {
    // clang-format off
    &_create<CryptoConfigEntryCheckBox>, // None
    &_create<CryptoConfigEntryLineEdit>, // String
    &_create<CryptoConfigEntrySpinBox>,  // Int
    &_create<CryptoConfigEntrySpinBox>,  // UInt
    &_create<CryptoConfigEntryPath>,     // Path
    nullptr,                             // Formerly URL
    nullptr,                             // LDAPURL
    &_create<CryptoConfigEntryDirPath>,  // DirPath
    // clang-format on
};

CryptoConfigEntryGUI *Kleo::CryptoConfigEntryGUIFactory::createEntryGUI(CryptoConfigModule *module,
                                                                        QGpgME::CryptoConfigEntry *entry,
                                                                        const QString &entryName,
                                                                        QGridLayout *glay,
                                                                        QWidget *widget)
{
    Q_ASSERT(entry);

    // try to lookup by path:
    const QString path = entry->path();
    for (unsigned int i = 0; i < numWidgetsByEntryName; ++i) {
        if (QRegularExpression::fromWildcard(QString::fromLatin1(widgetsByEntryName[i].entryGlob), Qt::CaseSensitive).match(path).hasMatch()) {
            return widgetsByEntryName[i].create(module, entry, entryName, glay, widget);
        }
    }

    // none found, so look up by type:
    const unsigned int argType = entry->argType();
    Q_ASSERT(argType < QGpgME::CryptoConfigEntry::NumArgType);
    if (entry->isList()) {
        if (const constructor create = listWidgets[argType]) {
            return create(module, entry, entryName, glay, widget);
        } else {
            qCWarning(KLEO_UI_LOG) << "No widget implemented for list of type" << entry->argType();
        }
    } else if (const constructor create = scalarWidgets[argType]) {
        return create(module, entry, entryName, glay, widget);
    } else {
        qCWarning(KLEO_UI_LOG) << "No widget implemented for type" << entry->argType();
    }

    return nullptr;
}

////

Kleo::CryptoConfigEntryGUI::CryptoConfigEntryGUI(CryptoConfigModule *module, QGpgME::CryptoConfigEntry *entry, const QString &entryName)
    : QObject(module)
    , mEntry(entry)
    , mName(entryName)
    , mChanged(false)
{
    connect(this, &CryptoConfigEntryGUI::changed, module, &CryptoConfigModule::changed);
}

QString Kleo::CryptoConfigEntryGUI::description() const
{
    QString descr = mEntry->description();
    if (descr.isEmpty()) { // happens for expert options
        // String does not need to be translated because the options itself
        // are also not translated
        return QStringLiteral("\"%1\"").arg(mName);
    }
    if (i18nc("Translate this to 'yes' or 'no' (use the English words!) "
              "depending on whether your language uses "
              "Sentence style capitalization in GUI labels (yes) or not (no). "
              "Context: We get some backend strings in that have the wrong "
              "capitalization (in English, at least) so we need to force the "
              "first character to upper-case. It is this behaviour you can "
              "control for your language with this translation.",
              "yes")
        == QLatin1String("yes")) {
        descr[0] = descr[0].toUpper();
    }
    return descr;
}

void Kleo::CryptoConfigEntryGUI::resetToDefault()
{
    mEntry->resetToDefault();
    load();
}

////

Kleo::CryptoConfigEntryLineEdit::CryptoConfigEntryLineEdit(CryptoConfigModule *module,
                                                           QGpgME::CryptoConfigEntry *entry,
                                                           const QString &entryName,
                                                           QGridLayout *glay,
                                                           QWidget *widget)
    : CryptoConfigEntryGUI(module, entry, entryName)
{
    const int row = glay->rowCount();
    mLineEdit = new KLineEdit(widget);
    QLabel *label = new QLabel(description(), widget);
    label->setBuddy(mLineEdit);
    glay->addWidget(label, row, 1);
    glay->addWidget(mLineEdit, row, 2);
    if (entry->isReadOnly()) {
        label->setEnabled(false);
        mLineEdit->setEnabled(false);
    } else {
        connect(mLineEdit, &KLineEdit::textChanged, this, &CryptoConfigEntryLineEdit::slotChanged);
    }
}

void Kleo::CryptoConfigEntryLineEdit::doSave()
{
    mEntry->setStringValue(mLineEdit->text());
}

void Kleo::CryptoConfigEntryLineEdit::doLoad()
{
    mLineEdit->setText(mEntry->stringValue());
}

////
/* Note: Do not use "guru" as debug level but use the value 10.  The
   former also enables the creation of hash dump files and thus leaves
   traces of plaintext on the disk.  */
static const struct {
    const KLazyLocalizedString label;
    const char *name;
} debugLevels[] = {
    {kli18n("0 - None"), "none"},
    {kli18n("1 - Basic"), "basic"},
    {kli18n("2 - Verbose"), "advanced"},
    {kli18n("3 - More Verbose"), "expert"},
    {kli18n("4 - All"), "10"},
};
static const unsigned int numDebugLevels = sizeof debugLevels / sizeof *debugLevels;

Kleo::CryptoConfigEntryDebugLevel::CryptoConfigEntryDebugLevel(CryptoConfigModule *module,
                                                               QGpgME::CryptoConfigEntry *entry,
                                                               const QString &entryName,
                                                               QGridLayout *glay,
                                                               QWidget *widget)
    : CryptoConfigEntryGUI(module, entry, entryName)
    , mComboBox(new QComboBox(widget))
{
    QLabel *label = new QLabel(i18n("Set the debugging level to"), widget);
    label->setBuddy(mComboBox);

    for (unsigned int i = 0; i < numDebugLevels; ++i) {
        mComboBox->addItem(KLocalizedString(debugLevels[i].label).toString());
    }

    if (entry->isReadOnly()) {
        label->setEnabled(false);
        mComboBox->setEnabled(false);
    } else {
        connect(mComboBox, &QComboBox::currentIndexChanged, this, &CryptoConfigEntryDebugLevel::slotChanged);
    }

    const int row = glay->rowCount();
    glay->addWidget(label, row, 1);
    glay->addWidget(mComboBox, row, 2);
}

void Kleo::CryptoConfigEntryDebugLevel::doSave()
{
    const unsigned int idx = mComboBox->currentIndex();
    if (idx < numDebugLevels) {
        mEntry->setStringValue(QLatin1String(debugLevels[idx].name));
    } else {
        mEntry->setStringValue(QString());
    }
}

void Kleo::CryptoConfigEntryDebugLevel::doLoad()
{
    const QString str = mEntry->stringValue();
    for (unsigned int i = 0; i < numDebugLevels; ++i) {
        if (str == QLatin1String(debugLevels[i].name)) {
            mComboBox->setCurrentIndex(i);
            return;
        }
    }
    mComboBox->setCurrentIndex(0);
}

////

Kleo::CryptoConfigEntryPath::CryptoConfigEntryPath(CryptoConfigModule *module,
                                                   QGpgME::CryptoConfigEntry *entry,
                                                   const QString &entryName,
                                                   QGridLayout *glay,
                                                   QWidget *widget)
    : CryptoConfigEntryGUI(module, entry, entryName)
    , mFileNameRequester(nullptr)
{
    const int row = glay->rowCount();
    mFileNameRequester = new FileNameRequester(widget);
    mFileNameRequester->setExistingOnly(false);
    mFileNameRequester->setFilter(QDir::Files);
    QLabel *label = new QLabel(description(), widget);
    label->setBuddy(mFileNameRequester);
    glay->addWidget(label, row, 1);
    glay->addWidget(mFileNameRequester, row, 2);
    if (entry->isReadOnly()) {
        label->setEnabled(false);
        mFileNameRequester->setEnabled(false);
    } else {
        connect(mFileNameRequester, &FileNameRequester::fileNameChanged, this, &CryptoConfigEntryPath::slotChanged);
    }
}

void Kleo::CryptoConfigEntryPath::doSave()
{
    mEntry->setURLValue(QUrl::fromLocalFile(mFileNameRequester->fileName()));
}

void Kleo::CryptoConfigEntryPath::doLoad()
{
    if (mEntry->urlValue().isLocalFile()) {
        mFileNameRequester->setFileName(mEntry->urlValue().toLocalFile());
    } else {
        mFileNameRequester->setFileName(mEntry->urlValue().toString());
    }
}

////

Kleo::CryptoConfigEntryDirPath::CryptoConfigEntryDirPath(CryptoConfigModule *module,
                                                         QGpgME::CryptoConfigEntry *entry,
                                                         const QString &entryName,
                                                         QGridLayout *glay,
                                                         QWidget *widget)
    : CryptoConfigEntryGUI(module, entry, entryName)
    , mFileNameRequester(nullptr)
{
    const int row = glay->rowCount();
    mFileNameRequester = new FileNameRequester(widget);
    mFileNameRequester->setExistingOnly(false);
    mFileNameRequester->setFilter(QDir::Dirs);
    QLabel *label = new QLabel(description(), widget);
    label->setBuddy(mFileNameRequester);
    glay->addWidget(label, row, 1);
    glay->addWidget(mFileNameRequester, row, 2);
    if (entry->isReadOnly()) {
        label->setEnabled(false);
        mFileNameRequester->setEnabled(false);
    } else {
        connect(mFileNameRequester, &FileNameRequester::fileNameChanged, this, &CryptoConfigEntryDirPath::slotChanged);
    }
}

void Kleo::CryptoConfigEntryDirPath::doSave()
{
    mEntry->setURLValue(QUrl::fromLocalFile(mFileNameRequester->fileName()));
}

void Kleo::CryptoConfigEntryDirPath::doLoad()
{
    mFileNameRequester->setFileName(mEntry->urlValue().toLocalFile());
}

////

Kleo::CryptoConfigEntrySpinBox::CryptoConfigEntrySpinBox(CryptoConfigModule *module,
                                                         QGpgME::CryptoConfigEntry *entry,
                                                         const QString &entryName,
                                                         QGridLayout *glay,
                                                         QWidget *widget)
    : CryptoConfigEntryGUI(module, entry, entryName)
{
    if (entry->argType() == QGpgME::CryptoConfigEntry::ArgType_None && entry->isList()) {
        mKind = ListOfNone;
    } else if (entry->argType() == QGpgME::CryptoConfigEntry::ArgType_UInt) {
        mKind = UInt;
    } else {
        Q_ASSERT(entry->argType() == QGpgME::CryptoConfigEntry::ArgType_Int);
        mKind = Int;
    }

    const int row = glay->rowCount();
    mNumInput = new QSpinBox(widget);
    QLabel *label = new QLabel(description(), widget);
    label->setBuddy(mNumInput);
    glay->addWidget(label, row, 1);
    glay->addWidget(mNumInput, row, 2);

    if (entry->isReadOnly()) {
        label->setEnabled(false);
        mNumInput->setEnabled(false);
    } else {
        mNumInput->setMinimum(mKind == Int ? std::numeric_limits<int>::min() : 0);
        mNumInput->setMaximum(std::numeric_limits<int>::max());
        connect(mNumInput, &QSpinBox::valueChanged, this, &CryptoConfigEntrySpinBox::slotChanged);
    }
}

void Kleo::CryptoConfigEntrySpinBox::doSave()
{
    int value = mNumInput->value();
    switch (mKind) {
    case ListOfNone:
        mEntry->setNumberOfTimesSet(value);
        break;
    case UInt:
        mEntry->setUIntValue(value);
        break;
    case Int:
        mEntry->setIntValue(value);
        break;
    }
}

void Kleo::CryptoConfigEntrySpinBox::doLoad()
{
    int value = 0;
    switch (mKind) {
    case ListOfNone:
        value = mEntry->numberOfTimesSet();
        break;
    case UInt:
        value = mEntry->uintValue();
        break;
    case Int:
        value = mEntry->intValue();
        break;
    }
    mNumInput->setValue(value);
}

////

Kleo::CryptoConfigEntryCheckBox::CryptoConfigEntryCheckBox(CryptoConfigModule *module,
                                                           QGpgME::CryptoConfigEntry *entry,
                                                           const QString &entryName,
                                                           QGridLayout *glay,
                                                           QWidget *widget)
    : CryptoConfigEntryGUI(module, entry, entryName)
{
    const int row = glay->rowCount();
    mCheckBox = new QCheckBox(widget);
    glay->addWidget(mCheckBox, row, 1, 1, 2);
    mCheckBox->setText(description());
    if (entry->isReadOnly()) {
        mCheckBox->setEnabled(false);
    } else {
        connect(mCheckBox, &QCheckBox::toggled, this, &CryptoConfigEntryCheckBox::slotChanged);
    }
}

void Kleo::CryptoConfigEntryCheckBox::doSave()
{
    mEntry->setBoolValue(mCheckBox->isChecked());
}

void Kleo::CryptoConfigEntryCheckBox::doLoad()
{
    mCheckBox->setChecked(mEntry->boolValue());
}

Kleo::CryptoConfigEntryLDAPURL::CryptoConfigEntryLDAPURL(CryptoConfigModule *module,
                                                         QGpgME::CryptoConfigEntry *entry,
                                                         const QString &entryName,
                                                         QGridLayout *glay,
                                                         QWidget *widget)
    : CryptoConfigEntryGUI(module, entry, entryName)
{
    mLabel = new QLabel(widget);
    mPushButton = new QPushButton(entry->isReadOnly() ? i18n("Show...") : i18n("Edit..."), widget);

    const int row = glay->rowCount();
    QLabel *label = new QLabel(description(), widget);
    label->setBuddy(mPushButton);
    glay->addWidget(label, row, 1);
    auto hlay = new QHBoxLayout;
    glay->addLayout(hlay, row, 2);
    hlay->addWidget(mLabel, 1);
    hlay->addWidget(mPushButton);

    if (entry->isReadOnly()) {
        mLabel->setEnabled(false);
    }
    connect(mPushButton, &QPushButton::clicked, this, &CryptoConfigEntryLDAPURL::slotOpenDialog);
}

void Kleo::CryptoConfigEntryLDAPURL::doLoad()
{
    setURLList(mEntry->urlValueList());
}

void Kleo::CryptoConfigEntryLDAPURL::doSave()
{
    mEntry->setURLValueList(mURLList);
}

void prepareURLCfgDialog(QDialog *dialog, DirectoryServicesWidget *dirserv, bool readOnly)
{
    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok, dialog);

    if (!readOnly) {
        buttonBox->addButton(QDialogButtonBox::Cancel);
        buttonBox->addButton(QDialogButtonBox::RestoreDefaults);

        QPushButton *defaultsBtn = buttonBox->button(QDialogButtonBox::RestoreDefaults);

        QObject::connect(defaultsBtn, &QPushButton::clicked, dirserv, &DirectoryServicesWidget::clear);
        QObject::connect(buttonBox, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
    }

    QObject::connect(buttonBox, &QDialogButtonBox::accepted, dialog, &QDialog::accept);

    auto layout = new QVBoxLayout;
    layout->addWidget(dirserv);
    layout->addWidget(buttonBox);
    dialog->setLayout(layout);
}

void Kleo::CryptoConfigEntryLDAPURL::slotOpenDialog()
{
    if (!gpgme_check_version("1.16.0")) {
        KMessageBox::error(mPushButton->parentWidget(),
                           i18n("Configuration of directory services is not possible "
                                "because the used gpgme libraries are too old."),
                           i18n("Sorry"));
        return;
    }

    // I'm a bad boy and I do it all on the stack. Enough classes already :)
    // This is just a simple dialog around the directory-services-widget
    QDialog dialog(mPushButton->parentWidget());
    dialog.setWindowTitle(i18nc("@title:window", "Configure Directory Services"));

    auto dirserv = new DirectoryServicesWidget(&dialog);

    prepareURLCfgDialog(&dialog, dirserv, mEntry->isReadOnly());

    dirserv->setReadOnly(mEntry->isReadOnly());

    std::vector<KeyserverConfig> servers;
    std::transform(std::cbegin(mURLList), std::cend(mURLList), std::back_inserter(servers), [](const auto &url) {
        return KeyserverConfig::fromUrl(url);
    });
    dirserv->setKeyservers(servers);

    if (dialog.exec()) {
        QList<QUrl> urls;
        const auto servers = dirserv->keyservers();
        std::transform(std::begin(servers), std::end(servers), std::back_inserter(urls), [](const auto &server) {
            return server.toUrl();
        });
        setURLList(urls);
        slotChanged();
    }
}

void Kleo::CryptoConfigEntryLDAPURL::setURLList(const QList<QUrl> &urlList)
{
    mURLList = urlList;
    if (mURLList.isEmpty()) {
        mLabel->setText(i18n("None configured"));
    } else {
        mLabel->setText(i18np("1 server configured", "%1 servers configured", mURLList.count()));
    }
}

#include "moc_cryptoconfigmodule_p.cpp"

#include "moc_cryptoconfigmodule.cpp"
