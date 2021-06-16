/*
    ui/directoryserviceswidget.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2001, 2002, 2004 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2017 Bundesamnt für Sicherheit in der Informationstechnik
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "directoryserviceswidget.h"

#include "editdirectoryservicedialog.h"

#include "kleo/keyserverconfig.h"
#include "utils/gnupg.h"

#include <KLocalizedString>

#include <QInputDialog>
#include <QListView>
#include <QMenu>
#include <QPointer>
#include <QPushButton>
#include <QToolButton>
#include <QVBoxLayout>

#include "kleo_ui_debug.h"

using namespace Kleo;

namespace
{

bool activeDirectoryIsSupported()
{
    return engineIsVersion(2, 2, 28, GpgME::GpgSMEngine);
}

bool isStandardActiveDirectory(const KeyserverConfig &keyserver)
{
    return (keyserver.authentication() == KeyserverAuthentication::ActiveDirectory)
        && keyserver.host().isEmpty();
}

bool keyserverIsEditable(const KeyserverConfig &keyserver)
{
    // standard AD is not editable
    return !isStandardActiveDirectory(keyserver);
}

class KeyserverModel : public QAbstractListModel
{
    Q_OBJECT
public:
    explicit KeyserverModel(QObject *parent = nullptr)
        : QAbstractListModel{parent}
    {
    }

    void setKeyservers(const std::vector<KeyserverConfig> &servers)
    {
        clear();
        beginInsertRows(QModelIndex(), 0, servers.size() - 1);
        m_items = servers;
        endInsertRows();
    }

    void addKeyserver(const KeyserverConfig &keyserver)
    {
        const auto row = m_items.size();
        beginInsertRows(QModelIndex(), row, row);
        m_items.push_back(keyserver);
        endInsertRows();
    }

    KeyserverConfig getKeyserver(unsigned int id)
    {
        if (id >= m_items.size()) {
            qCDebug(KLEO_UI_LOG) << __func__ << "invalid keyserver id:" << id;
            return {};
        }

        return m_items[id];
    }

    void updateKeyserver(unsigned int id, const KeyserverConfig &keyserver)
    {
        if (id >= m_items.size()) {
            qCDebug(KLEO_UI_LOG) << __func__ << "invalid keyserver id:" << id;
            return;
        }

        m_items[id] = keyserver;
        Q_EMIT dataChanged(index(id), index(id));
    }

    void deleteKeyserver(unsigned int id)
    {
        if (id >= m_items.size()) {
            qCDebug(KLEO_UI_LOG) << __func__ << "invalid keyserver id:" << id;
            return;
        }

        beginRemoveRows(QModelIndex(), id, id);
        m_items.erase(m_items.begin() + id);
        endRemoveRows();
    }

    void clear()
    {
        if (m_items.empty()) {
            return;
        }
        beginRemoveRows(QModelIndex(), 0, m_items.size() - 1);
        m_items.clear();
        endRemoveRows();
    }

    int rowCount(const QModelIndex & = QModelIndex()) const override
    {
        return m_items.size();
    }

    QVariant data(const QModelIndex &index, int role) const override
    {
        if (!index.isValid()) {
            return {};
        }
        switch (role) {
        case Qt::DisplayRole:
        case Qt::EditRole: {
            const auto keyserver = m_items[index.row()];
            return isStandardActiveDirectory(keyserver) ? i18n("Active Directory") : keyserver.host();
        }
        }
        return {};
    }

    bool hasActiveDirectory()
    {
        // check whether any of the model items represents an Active Directory keyserver
        return std::any_of(std::cbegin(m_items), std::cend(m_items), isStandardActiveDirectory);
    }

private:
    using QAbstractListModel::setData;

private:
    std::vector<KeyserverConfig> m_items;
};
}

class DirectoryServicesWidget::Private
{
    DirectoryServicesWidget *const q;

    struct {
        QListView *keyserverList = nullptr;
        QToolButton *newButton = nullptr;
        QAction *addActiveDirectoryAction = nullptr;
        QAction *addLdapServerAction = nullptr;
        QPushButton *editButton = nullptr;
        QPushButton *deleteButton = nullptr;
    } ui;
    KeyserverModel *keyserverModel = nullptr;
    bool readOnly = false;

public:
    Private(DirectoryServicesWidget *qq)
        : q(qq)
    {
        auto mainLayout = new QVBoxLayout{q};

        auto gridLayout = new QGridLayout{};
        gridLayout->setColumnStretch(0, 1);
        gridLayout->setRowStretch(1, 1);

        keyserverModel = new KeyserverModel{q};
        ui.keyserverList = new QListView();
        ui.keyserverList->setModel(keyserverModel);
        ui.keyserverList->setModelColumn(0);
        ui.keyserverList->setSelectionBehavior(QAbstractItemView::SelectRows);
        ui.keyserverList->setSelectionMode(QAbstractItemView::SingleSelection);
        ui.keyserverList->setWhatsThis(i18nc("@info:whatsthis",
                                             "This is a list of all directory services that are configured for use with X.509."));
        gridLayout->addWidget(ui.keyserverList, 1, 0);

        auto groupsButtonLayout = new QVBoxLayout();

        auto menu = new QMenu{q};
        ui.addActiveDirectoryAction = menu->addAction(i18n("Active Directory"), [this] () { addActiveDirectory(); });
        ui.addActiveDirectoryAction->setToolTip(i18nc("@info:tooltip",
                                                      "Click to use a directory service running on your Active Directory. "
                                                      "This works only on Windows and requires GnuPG 2.2.28 or later."));
        ui.addActiveDirectoryAction->setEnabled(activeDirectoryIsSupported());
        ui.addLdapServerAction = menu->addAction(i18n("LDAP Server"), [this] () { addLdapServer(); });
        ui.addLdapServerAction->setToolTip(i18nc("@info:tooltip", "Click to add a directory service provided by an LDAP server."));
        ui.newButton = new QToolButton{q};
        ui.newButton->setText(i18n("Add"));
        ui.newButton->setToolTip(i18nc("@info:tooltip", "Click to add a directory service."));
        ui.newButton->setWhatsThis(i18nc("@info:whatsthis",
                                         "Click this button to add a directory service to the list of services. "
                                         "The change will only take effect once you acknowledge the configuration dialog."));
        ui.newButton->setToolButtonStyle(Qt::ToolButtonTextOnly);
        ui.newButton->setPopupMode(QToolButton::InstantPopup);
        ui.newButton->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Fixed); // expand horizontally like the QPushButtons
        ui.newButton->setMenu(menu);
        groupsButtonLayout->addWidget(ui.newButton);

        ui.editButton = new QPushButton(i18n("Edit"));
        ui.editButton->setToolTip(i18nc("@info:tooltip", "Click to edit the selected service."));
        ui.editButton->setWhatsThis(i18nc("@info:whatsthis",
                                          "Click this button to edit the settings of the currently selected directory service. "
                                          "The changes will only take effect once you acknowledge the configuration dialog."));
        ui.editButton->setEnabled(false);
        groupsButtonLayout->addWidget(ui.editButton);

        ui.deleteButton = new QPushButton(i18n("Delete"));
        ui.deleteButton->setToolTip(i18nc("@info:tooltip", "Click to remove the selected service."));
        ui.deleteButton->setWhatsThis(i18nc("@info:whatsthis",
                                            "Click this button to remove the currently selected directory service. "
                                            "The change will only take effect once you acknowledge the configuration dialog."));
        ui.deleteButton->setEnabled(false);
        groupsButtonLayout->addWidget(ui.deleteButton);

        groupsButtonLayout->addStretch(1);

        gridLayout->addLayout(groupsButtonLayout, 1, 1);

        mainLayout->addLayout(gridLayout, /*stretch=*/ 1);

        connect(keyserverModel, &QAbstractItemModel::dataChanged, q, [this] () { modelChanged(); });
        connect(keyserverModel, &QAbstractItemModel::rowsInserted, q, [this] () { modelChanged(); });
        connect(keyserverModel, &QAbstractItemModel::rowsRemoved, q, [this] () { modelChanged(); });
        connect(ui.keyserverList->selectionModel(), &QItemSelectionModel::selectionChanged,
                q, [this] () { selectionChanged(); });
        connect(ui.keyserverList, &QListView::doubleClicked,
                q, [this] (const QModelIndex &index) { editKeyserver(index); });
        connect(ui.editButton, &QPushButton::clicked, q, [this] () { editKeyserver(); });
        connect(ui.deleteButton, &QPushButton::clicked, q, [this] () { deleteKeyserver(); });
    }

    void setReadOnly(bool ro)
    {
        readOnly = ro;
        updateActions();
    }

    void setKeyservers(const std::vector<KeyserverConfig> &servers)
    {
        keyserverModel->setKeyservers(servers);
    }

    std::vector<KeyserverConfig> keyservers() const
    {
        std::vector<KeyserverConfig> result;
        result.reserve(keyserverModel->rowCount());
        for (int row = 0; row < keyserverModel->rowCount(); ++row) {
            result.push_back(keyserverModel->getKeyserver(row));
        }
        return result;
    }

    void clear()
    {
        if (keyserverModel->rowCount() == 0) {
            return;
        }
        keyserverModel->clear();
    }

private:
    auto selectedIndex()
    {
        const auto indexes = ui.keyserverList->selectionModel()->selectedRows();
        return indexes.empty() ? QModelIndex() : indexes[0];
    }

    void modelChanged()
    {
        updateActions();
        Q_EMIT q->changed();
    }

    void selectionChanged()
    {
        updateActions();
    }

    void updateActions()
    {
        const auto index = selectedIndex();
        ui.newButton->setEnabled(!readOnly);
        ui.addActiveDirectoryAction->setEnabled(activeDirectoryIsSupported() && !keyserverModel->hasActiveDirectory());
        ui.editButton->setEnabled(!readOnly && index.isValid() && keyserverIsEditable(keyserverModel->getKeyserver(index.row())));
        ui.deleteButton->setEnabled(!readOnly && index.isValid());
    }

    void handleEditKeyserverDialogResult(const int id, const EditDirectoryServiceDialog *dialog)
    {
        if (id >= 0) {
            keyserverModel->updateKeyserver(id, dialog->keyserver());
        } else {
            keyserverModel->addKeyserver(dialog->keyserver());
        }
    }

    void showEditKeyserverDialog(const int id, const KeyserverConfig &keyserver, const QString &windowTitle)
    {
        QPointer<EditDirectoryServiceDialog> dialog{new EditDirectoryServiceDialog{q}};
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setWindowModality(Qt::WindowModal);
        dialog->setWindowTitle(windowTitle);
        dialog->setKeyserver(keyserver);

        connect(dialog, &QDialog::accepted, q, [dialog, id, this] {
            handleEditKeyserverDialogResult(id, dialog);
        });

        dialog->show();
    }

    void addActiveDirectory()
    {
        KeyserverConfig keyserver;
        keyserver.setAuthentication(KeyserverAuthentication::ActiveDirectory);
        keyserverModel->addKeyserver(keyserver);
    }

    void addLdapServer()
    {
        showEditKeyserverDialog(-1, {}, i18nc("@title:window", "LDAP Directory Service"));
    }

    void editKeyserver(const QModelIndex &index = {})
    {
        const auto serverIndex = index.isValid() ? index : selectedIndex();
        if (!serverIndex.isValid()) {
            qCDebug(KLEO_UI_LOG) << __func__ << "selection is empty";
            return;
        }
        const auto id = serverIndex.row();
        const KeyserverConfig keyserver = keyserverModel->getKeyserver(id);
        if (!keyserverIsEditable(keyserver)) {
            qCDebug(KLEO_UI_LOG) << __func__ << "selected keyserver (id:" << id << ") cannot be modified";
            return;
        }

        showEditKeyserverDialog(id, keyserver, i18nc("@title:window", "LDAP Directory Service"));
    }

    void deleteKeyserver()
    {
        const QModelIndex serverIndex = selectedIndex();
        if (!serverIndex.isValid()) {
            qCDebug(KLEO_UI_LOG) << __func__ << "selection is empty";
            return;
        }
        keyserverModel->deleteKeyserver(serverIndex.row());
    }
};

DirectoryServicesWidget::DirectoryServicesWidget(QWidget *parent)
    : QWidget{parent}
    , d{std::make_unique<Private>(this)}
{
}

DirectoryServicesWidget::~DirectoryServicesWidget() = default;

void DirectoryServicesWidget::setKeyservers(const std::vector<KeyserverConfig> &servers)
{
    d->setKeyservers(servers);
}

std::vector<KeyserverConfig> DirectoryServicesWidget::keyservers() const
{
    return d->keyservers();
}

void DirectoryServicesWidget::setReadOnly(bool readOnly)
{
    d->setReadOnly(readOnly);
}

void DirectoryServicesWidget::clear()
{
    d->clear();
}

#include "directoryserviceswidget.moc"
