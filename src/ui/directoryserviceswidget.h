/*
    directoryserviceswidget.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2001, 2002, 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifndef DIRECTORYSERVICESWIDGET_H
#define DIRECTORYSERVICESWIDGET_H

#include "kleo_export.h"
#include <QUrl>
#include <QWidget>

namespace Kleo
{

class KLEO_EXPORT DirectoryServicesWidget : public QWidget
{
    Q_OBJECT
public:
    explicit DirectoryServicesWidget(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~DirectoryServicesWidget();

    enum Scheme {
        NoScheme = 0,
        HKP      = 1,
        HTTP     = 2,
        FTP      = 4,
        LDAP     = 8,

        AllSchemes = HKP | HTTP | FTP | LDAP
    };
    Q_DECLARE_FLAGS(Schemes, Scheme)

    enum Protocol {
        NoProtocol = 0,
        X509Protocol = 1,
        OpenPGPProtocol = 2,

        AllProtocols = X509Protocol | OpenPGPProtocol
    };
    Q_DECLARE_FLAGS(Protocols, Protocol)

    void setAllowedSchemes(Schemes schemes);
    Schemes allowedSchemes() const;

    void setAllowedProtocols(Protocols protocols);
    Protocols allowedProtocols() const;

    void setX509Allowed(bool allowed);
    void setOpenPGPAllowed(bool allowed);

    void setReadOnlyProtocols(Protocols protocols);
    Protocols readOnlyProtocols() const;

    void setOpenPGPReadOnly(bool ro);
    void setX509ReadOnly(bool ro);

    void addOpenPGPServices(const QList<QUrl> &urls);
    QList<QUrl> openPGPServices() const;

    void addX509Services(const QList<QUrl> &urls);
    QList<QUrl> x509Services() const;

public Q_SLOTS:
    void clear();

Q_SIGNALS:
    void changed();

private:
    class Private;
    Private *const d;
    Q_PRIVATE_SLOT(d, void slotNewX509Clicked())
    Q_PRIVATE_SLOT(d, void slotDeleteClicked())
    Q_PRIVATE_SLOT(d, void slotSelectionChanged())
    Q_PRIVATE_SLOT(d, void slotShowUserAndPasswordToggled(bool))
};

}

inline void Kleo::DirectoryServicesWidget::setOpenPGPAllowed(bool allowed)
{
    if (allowed) {
        setAllowedProtocols(allowedProtocols() | OpenPGPProtocol);
    } else {
        setAllowedProtocols(allowedProtocols() & ~OpenPGPProtocol);
    }
}

inline void Kleo::DirectoryServicesWidget::setX509Allowed(bool allowed)
{
    if (allowed) {
        setAllowedProtocols(allowedProtocols() | X509Protocol);
    } else {
        setAllowedProtocols(allowedProtocols() & ~X509Protocol);
    }
}

inline void Kleo::DirectoryServicesWidget::setOpenPGPReadOnly(bool ro)
{
    if (ro) {
        setReadOnlyProtocols(readOnlyProtocols() | OpenPGPProtocol);
    } else {
        setReadOnlyProtocols(readOnlyProtocols() & ~OpenPGPProtocol);
    }
}

inline void Kleo::DirectoryServicesWidget::setX509ReadOnly(bool ro)
{
    if (ro) {
        setReadOnlyProtocols(readOnlyProtocols() | X509Protocol);
    } else {
        setReadOnlyProtocols(readOnlyProtocols() & ~X509Protocol);
    }
}

#endif // DIRECTORYSERVICESWIDGET_H
