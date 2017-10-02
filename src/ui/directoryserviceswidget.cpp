/*
    directoryserviceswidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    Copyright (c) 2001,2002,2004 Klarävdalens Datakonsult AB
    Copyright (c) 2017 Bundesamnt für Sicherheit in der Informationstechnik

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

#include "directoryserviceswidget.h"

#include "ui_directoryserviceswidget.h"

#include "kleo_ui_debug.h"

#include <KLocalizedString>

#include <QItemDelegate>
#include <QAbstractTableModel>
#include <QSpinBox>
#include <QHeaderView>

#include <vector>

#include <climits>
#include <algorithm>
#include <functional>

#include <gpgme++/engineinfo.h>

using namespace Kleo;

namespace
{

static QUrl defaultX509Service()
{
    QUrl url;
    url.setScheme(QStringLiteral("ldap"));
    url.setHost(i18nc("default server name, keep it a valid domain name, ie. no spaces", "server"));
    return url;
}
static QUrl defaultOpenPGPService()
{
    QUrl url;
    if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.1.16") {
        url.setScheme(QStringLiteral("hkp"));
        url.setHost(QStringLiteral("keys.gnupg.net"));
    } else {
        url.setScheme(QStringLiteral("hkps"));
        url.setHost(QStringLiteral("hkps.pool.sks-keyservers.net"));
    }
   return url;
}

static bool is_ldap_scheme(const QUrl &url)
{
    const QString scheme = url.scheme();
    return QString::compare(scheme, QStringLiteral("ldap"),  Qt::CaseInsensitive) == 0
           || QString::compare(scheme, QStringLiteral("ldaps"), Qt::CaseInsensitive) == 0;
}

static const struct {
    const char label[6];
    unsigned short port;
    DirectoryServicesWidget::Scheme base;
} protocols[] = {
    { I18N_NOOP("hkp"), 11371, DirectoryServicesWidget::HKP  },
    { I18N_NOOP("http"),   80, DirectoryServicesWidget::HTTP },
    { I18N_NOOP("https"), 443, DirectoryServicesWidget::HTTP },
    { I18N_NOOP("ftp"),    21, DirectoryServicesWidget::FTP  },
    { I18N_NOOP("ftps"),  990, DirectoryServicesWidget::FTP  },
    { I18N_NOOP("ldap"),  389, DirectoryServicesWidget::LDAP },
    { I18N_NOOP("ldaps"), 636, DirectoryServicesWidget::LDAP },
};
static const unsigned int numProtocols = sizeof protocols / sizeof * protocols;

static unsigned short default_port(const QString &scheme)
{
    for (unsigned int i = 0; i < numProtocols; ++i)
        if (QString::compare(scheme, QLatin1String(protocols[i].label), Qt::CaseInsensitive) == 0) {
            return protocols[i].port;
        }
    return 0;
}

static QString display_scheme(const QUrl &url)
{
    if (url.scheme().isEmpty()) {
        return QStringLiteral("hkp");
    } else {
        return url.scheme();
    }
}

static QString display_host(const QUrl &url)
{
    // work around "subkeys.pgp.net" being interpreted as a path, not host
    if (url.host().isEmpty()) {
        return url.path();
    } else {
        return url.host();
    }
}

static unsigned short display_port(const QUrl &url)
{
    if (url.port() > 0) {
        return url.port();
    } else {
        return default_port(display_scheme(url));
    }
}

static QRect calculate_geometry(const QRect &cell, const QSize &sizeHint)
{
    const int height = qMax(cell.height(), sizeHint.height());
    return QRect(cell.left(), cell.top() - (height - cell.height()) / 2,
                 cell.width(), height);
}

/* The Model contains a bit historic cruft because in the past it was
 * thought to be a good idea to combine openPGP and X509 in a single
 * table although while you can have multiple X509 Keyservers there can
 * only be one OpenPGP Keyserver. So the OpenPGP Keyserver is now a
 * single lineedit. */
class Model : public QAbstractTableModel
{
    Q_OBJECT
public:
    explicit Model(QObject *parent = nullptr)
        : QAbstractTableModel(parent),
          m_items(),
          m_x509ReadOnly(false),
          m_schemes(DirectoryServicesWidget::LDAP)
    {

    }

    void setX509ReadOnly(bool ro)
    {
        if (ro == m_x509ReadOnly) {
            return;
        }
        m_x509ReadOnly = ro;
        for (unsigned int row = 0, end = rowCount(); row != end; ++row) {
            Q_EMIT dataChanged(index(row, 0), index(row, NumColumns));
        }
    }

    QModelIndex addX509Service(const QUrl &url, bool force = false)
    {
        const auto it = force ? m_items.end() : findExistingUrl(url);
        unsigned int row;
        if (it != m_items.end()) {
            // existing item:
            row = it - m_items.begin();
            Q_EMIT dataChanged(index(row, 0), index(row, NumColumns));
        } else {
            // append new item
            row = m_items.size();
            beginInsertRows(QModelIndex(), row, row);
            m_items.push_back(url);
            endInsertRows();
        }
        return index(row, firstEditableColumn(row));
    }

    unsigned int numServices() const
    {
        return m_items.size();
    }
    QUrl          service(unsigned int row) const
    {
        return row < m_items.size() ?  m_items[row] : QUrl();
    }

    enum Columns {
        Host,
        Port,
        BaseDN,
        UserName,
        Password,

        NumColumns
    };

    QModelIndex duplicateRow(unsigned int row)
    {
        if (row >= m_items.size()) {
            return QModelIndex();
        }

        beginInsertRows(QModelIndex(), row + 1, row + 1);
        m_items.insert(m_items.begin() + row + 1, m_items[row]);
        endInsertRows();
        return index(row + 1, 0);
    }

    void deleteRow(unsigned int row)
    {
        if (row >= m_items.size()) {
            return;
        }

        beginRemoveRows(QModelIndex(), row, row);
        m_items.erase(m_items.begin() + row);
        endInsertRows();
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

    int columnCount(const QModelIndex & = QModelIndex()) const override
    {
        return NumColumns;
    }
    int rowCount(const QModelIndex & = QModelIndex()) const override
    {
        return m_items.size();
    }

    QVariant data(const QModelIndex &idx, int role) const override;
    QVariant headerData(int section, Qt::Orientation o, int role) const override;

    Qt::ItemFlags flags(const QModelIndex &idx) const override;
    bool setData(const QModelIndex &idx, const QVariant &value, int role) override;

private:
    bool doSetData(unsigned int row, unsigned int column, const QVariant &value, int role);

    static QString toolTipForColumn(int column);
    bool isLdapRow(unsigned int row) const;
    int firstEditableColumn(unsigned int) const
    {
        return Host;
    }

private:
    std::vector<QUrl> m_items;
    bool m_x509ReadOnly    : 1;
    DirectoryServicesWidget::Schemes m_schemes;

private:
    std::vector<QUrl>::iterator findExistingUrl(const QUrl &url)
    {
        return std::find_if(m_items.begin(), m_items.end(),
                            [&url](const QUrl &item) {
                                const QUrl &lhs = url;
                                const QUrl &rhs = item;
                                return QString::compare(display_scheme(lhs), display_scheme(rhs), Qt::CaseInsensitive) == 0
                                    && QString::compare(display_host(lhs), display_host(rhs), Qt::CaseInsensitive) == 0
                                    && lhs.port() == rhs.port()
                                    && lhs.userName() == rhs.userName()
                                    // ... ignore password...
                                    && (!is_ldap_scheme(lhs)
                                        || lhs.query() == rhs.query());
                            });
    }
};

class Delegate : public QItemDelegate
{
    Q_OBJECT
public:
    explicit Delegate(QObject *parent = nullptr)
        : QItemDelegate(parent),
          m_schemes(DirectoryServicesWidget::LDAP)
    {

    }

    void setAllowedSchemes(const DirectoryServicesWidget::Schemes schemes)
    {
        m_schemes = schemes;
    }
    DirectoryServicesWidget::Schemes allowedSchemes() const
    {
        return m_schemes;
    }

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &idx) const override
    {
        switch (idx.column()) {
        case Model::Port:
            return createPortWidget(parent);
        }
        return QItemDelegate::createEditor(parent, option, idx);
    }

    void setEditorData(QWidget *editor, const QModelIndex &idx) const override
    {
        switch (idx.column()) {
        case Model::Port:
            setPortEditorData(qobject_cast<QSpinBox *>(editor), idx.data(Qt::EditRole).toInt());
            break;
        default:
            QItemDelegate::setEditorData(editor, idx);
            break;
        }
    }

    void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &idx) const override
    {
        switch (idx.column()) {
        case Model::Port:
            setPortModelData(qobject_cast<QSpinBox *>(editor), model, idx);
            break;
        default:
            QItemDelegate::setModelData(editor, model, idx);
            break;
        }
    }

    void updateEditorGeometry(QWidget *editor, const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        if (index.column() == Model::Port) {
            editor->setGeometry(calculate_geometry(option.rect, editor->sizeHint()));
        } else {
            QItemDelegate::updateEditorGeometry(editor, option, index);
        }
    }

private:
    QWidget *createPortWidget(QWidget *parent) const
    {
        QSpinBox *sb = new QSpinBox(parent);
        sb->setRange(1, USHRT_MAX);   // valid port numbers
        return sb;
    }
    void setPortEditorData(QSpinBox *sb, unsigned short port) const
    {
        Q_ASSERT(sb);
        sb->setValue(port);
    }
    void setPortModelData(const QSpinBox *sb, QAbstractItemModel *model, const QModelIndex &idx) const
    {
        Q_ASSERT(sb);
        Q_ASSERT(model);
        model->setData(idx, sb->value());
    }

private:
    DirectoryServicesWidget::Schemes m_schemes;
};

}

class DirectoryServicesWidget::Private
{
    friend class ::Kleo::DirectoryServicesWidget;
    DirectoryServicesWidget *const q;
public:
    explicit Private(DirectoryServicesWidget *qq)
        : q(qq),
          protocols(AllProtocols),
          readOnlyProtocols(NoProtocol),
          model(),
          delegate(),
          ui(q)
    {
        ui.treeView->setModel(&model);
        ui.treeView->setItemDelegate(&delegate);

        ui.pgpKeyserver->setPlaceholderText(defaultOpenPGPService().toString());

        connect(&model, &QAbstractItemModel::dataChanged, q, &DirectoryServicesWidget::changed);
        connect(&model, &QAbstractItemModel::rowsInserted, q, &DirectoryServicesWidget::changed);
        connect(&model, &QAbstractItemModel::rowsRemoved, q, &DirectoryServicesWidget::changed);
        connect(ui.treeView->selectionModel(), &QItemSelectionModel::selectionChanged,
                q, [this]() { slotSelectionChanged(); });
        connect(ui.pgpKeyserver, &QLineEdit::textChanged, q, &DirectoryServicesWidget::changed);

        slotShowUserAndPasswordToggled(false);
    }

private:
    void edit(const QModelIndex &index)
    {
        if (index.isValid()) {
            ui.treeView->clearSelection();
            ui.treeView->selectionModel()->setCurrentIndex(index, QItemSelectionModel::Select | QItemSelectionModel::Rows);
            ui.treeView->edit(index);
        }
    }
    void slotNewX509Clicked()
    {
        edit(model.addX509Service(defaultX509Service(), true));
    }
    void slotDeleteClicked()
    {
        model.deleteRow(selectedRow());
    }
    void slotSelectionChanged()
    {
        enableDisableActions();
    }
    void slotShowUserAndPasswordToggled(bool on)
    {
        QHeaderView *const hv = ui.treeView->header();
        Q_ASSERT(hv);
        hv->setSectionHidden(Model::UserName, !on);
        hv->setSectionHidden(Model::Password, !on);
    }

    int selectedRow() const
    {
        const QModelIndexList mil = ui.treeView->selectionModel()->selectedRows();
        return mil.empty() ? -1 : mil.front().row();
    }
    int currentRow() const
    {
        const QModelIndex idx = ui.treeView->selectionModel()->currentIndex();
        return idx.isValid() ? idx.row() : -1;
    }

    void enableDisableActions()
    {
        const bool x509 = (protocols & X509Protocol) && !(readOnlyProtocols & X509Protocol);
        const bool pgp  = (protocols & OpenPGPProtocol) && !(readOnlyProtocols & OpenPGPProtocol);
        ui.newTB->setEnabled(x509);
        ui.pgpKeyserver->setEnabled(pgp);
        const int row = selectedRow();
        ui.deleteTB->setEnabled(row >= 0 && !(readOnlyProtocols & X509Protocol));
    }

private:
    Protocols protocols;
    Protocols readOnlyProtocols;
    Model model;
    Delegate delegate;
    struct UI : Ui_DirectoryServicesWidget {

        explicit UI(DirectoryServicesWidget *q)
            : Ui_DirectoryServicesWidget()
        {
            setupUi(q);
        }

    } ui;
};

DirectoryServicesWidget::DirectoryServicesWidget(QWidget *p, Qt::WindowFlags f)
    : QWidget(p, f), d(new Private(this))
{

}

DirectoryServicesWidget::~DirectoryServicesWidget()
{
    delete d;
}

void DirectoryServicesWidget::setAllowedSchemes(Schemes schemes)
{
    d->delegate.setAllowedSchemes(schemes);
}

DirectoryServicesWidget::Schemes DirectoryServicesWidget::allowedSchemes() const
{
    return d->delegate.allowedSchemes();
}

void DirectoryServicesWidget::setAllowedProtocols(Protocols protocols)
{
    if (d->protocols == protocols) {
        return;
    }
    d->protocols = protocols;
    d->enableDisableActions();
}

DirectoryServicesWidget::Protocols DirectoryServicesWidget::allowedProtocols() const
{
    return d->protocols;
}

void DirectoryServicesWidget::setReadOnlyProtocols(Protocols protocols)
{
    if (d->readOnlyProtocols == protocols) {
        return;
    }
    d->readOnlyProtocols = protocols;
    d->model.setX509ReadOnly(protocols & X509Protocol);
    d->enableDisableActions();
}

DirectoryServicesWidget::Protocols DirectoryServicesWidget::readOnlyProtocols() const
{
    return d->readOnlyProtocols;
}

void DirectoryServicesWidget::addOpenPGPServices(const QList<QUrl> &urls)
{
    if (urls.size() > 1) {
        qCWarning(KLEO_UI_LOG) << "More then one PGP Server, Ignoring all others.";
    }
    if (urls.size()) {
        d->ui.pgpKeyserver->setText(urls[0].toString());
    }
}

QList<QUrl> DirectoryServicesWidget::openPGPServices() const
{
    QList<QUrl> result;
    const QString pgpStr = d->ui.pgpKeyserver->text();
    if (pgpStr.contains(QStringLiteral("://"))) {
        // Maybe validate here? Otoh maybe gnupg adds support for more schemes
        // then we know about in the future.
        result.push_back(QUrl::fromUserInput(pgpStr));
    } else if (!pgpStr.isEmpty()) {
        result.push_back(QUrl::fromUserInput(QStringLiteral("hkp://") + pgpStr));
    }
    return result;
}

void DirectoryServicesWidget::addX509Services(const QList<QUrl> &urls)
{
    for (const QUrl &url : urls) {
        d->model.addX509Service(url);
    }
}

QList<QUrl> DirectoryServicesWidget::x509Services() const
{
    QList<QUrl> result;
    for (unsigned int i = 0, end = d->model.numServices(); i != end; ++i) {
        result.push_back(d->model.service(i));
    }
    return result;
}

void DirectoryServicesWidget::clear()
{
    if (!d->model.numServices()) {
        return;
    }
    d->model.clear();
    d->ui.pgpKeyserver->setText(QString());
    Q_EMIT changed();
}

//
// Model
//

QVariant Model::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal)
        if (role == Qt::ToolTipRole) {
            return toolTipForColumn(section);
        } else if (role == Qt::DisplayRole)
            switch (section) {
            case Host:     return i18n("Server Name");
            case Port:     return i18n("Server Port");
            case BaseDN:   return i18n("Base DN");
            case UserName: return i18n("User Name");
            case Password: return i18n("Password");
            default:       return QVariant();
            }
        else {
            return QVariant();
        }
    else {
        return QAbstractTableModel::headerData(section, orientation, role);
    }
}

QVariant Model::data(const QModelIndex &index, int role) const
{
    const unsigned int row = index.row();
    if (index.isValid() && row < m_items.size())
        switch (role) {
        case Qt::ToolTipRole: {
            const QString tt = toolTipForColumn(index.column());
            if (!m_x509ReadOnly) {
                return tt;
            } else
                return tt.isEmpty()
                       ? i18n("(read-only)")
                       : i18nc("amended tooltip; %1: original tooltip",
                               "%1 (read-only)", tt);
        }
        case Qt::DisplayRole:
        case Qt::EditRole:
            switch (index.column()) {
            case Host:
                return display_host(m_items[row]);
            case Port:
                return display_port(m_items[row]);
            case BaseDN:
                if (isLdapRow(row)) {
                    return m_items[row].query();
                } else {
                    return QVariant();
                }
            case UserName:
                return m_items[row].userName();
            case Password:
                return m_items[row].password();
            default:
                return QVariant();
            }
        }
    return QVariant();
}

bool Model::isLdapRow(unsigned int row) const
{
    if (row >= m_items.size()) {
        return false;
    }
    return is_ldap_scheme(m_items[row]);
}

Qt::ItemFlags Model::flags(const QModelIndex &index) const
{
    const unsigned int row = index.row();
    Qt::ItemFlags flags = QAbstractTableModel::flags(index);
    if (m_x509ReadOnly) {
        flags &= ~Qt::ItemIsSelectable;
    }
    if (index.isValid() && row < m_items.size())
        switch (index.column()) {
        case Host:
        case Port:
            if (m_x509ReadOnly) {
                return flags & ~(Qt::ItemIsEditable | Qt::ItemIsEnabled);
            } else {
                return flags | Qt::ItemIsEditable;
            }
        case BaseDN:
            if (isLdapRow(row) && !m_x509ReadOnly) {
                return flags | Qt::ItemIsEditable;
            } else {
                return flags & ~(Qt::ItemIsEditable | Qt::ItemIsEnabled);
            }
        case UserName:
        case Password:
            if (m_x509ReadOnly) {
                return flags & ~(Qt::ItemIsEditable | Qt::ItemIsEnabled);
            } else {
                return flags | Qt::ItemIsEditable;
            }
        }
    return flags;
}

bool Model::setData(const QModelIndex &idx, const QVariant &value, int role)
{
    const unsigned int row = idx.row();
    if (!idx.isValid() || row >= m_items.size()) {
        return false;
    }
    if (m_x509ReadOnly) {
        return false;
    }
    if (!doSetData(row, idx.column(), value, role)) {
        return false;
    }
    Q_EMIT dataChanged(idx, idx);
    return true;
}

bool Model::doSetData(unsigned int row, unsigned int column, const QVariant &value, int role)
{
    if (role == Qt::EditRole)
        switch (column) {
        case Host:
            if (display_host(m_items[row]) != m_items[row].host()) {
                m_items[row].setScheme(display_scheme(m_items[row]));
            }
            m_items[row].setHost(value.toString());
            return true;
        case Port:
            if (value.toUInt() == default_port(display_scheme(m_items[row]))) {
                m_items[row].setPort(-1);
            } else {
                m_items[row].setPort(value.toUInt());
            }
            return true;
        case BaseDN:
            if (value.toString().isEmpty()) {
                m_items[row].setPath(QString());
                m_items[row].setQuery(QString());
            } else {
                m_items[row].setQuery(value.toString());
            }
            return true;
        case UserName:
            m_items[row].setUserName(value.toString());
            return true;
        case Password:
            m_items[row].setPassword(value.toString());
            return true;
        }
    return false;
}


// static
QString Model::toolTipForColumn(int column)
{
    switch (column) {
    case Host:     return i18n("Enter the name or IP address of the server "
                                   "hosting the directory service.");
    case Port:     return i18n("<b>(Optional, the default is fine in most cases)</b> "
                                   "Pick the port number the directory service is "
                                   "listening on.");
    case BaseDN:   return i18n("<b>(Only for LDAP)</b> "
                                   "Enter the base DN for this LDAP server to "
                                   "limit searches to only that subtree of the directory.");
    case UserName: return i18n("<b>(Optional)</b> "
                                   "Enter your user name here, if needed.");
    case Password: return i18n("<b>(Optional, not recommended)</b> "
                                   "Enter your password here, if needed. "
                                   "Note that the password will be saved in the clear "
                                   "in a config file in your home directory.");
    default:
        return QString();
    }
}

#include "directoryserviceswidget.moc"
#include "moc_directoryserviceswidget.cpp"
