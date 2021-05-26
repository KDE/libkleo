/*
    cryptoconfigmodule.h

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2004, 2005 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"
#include <kpagedialog.h>
#include <QList>

namespace QGpgME
{
class CryptoConfig;
} // namespace QGpgME

namespace Kleo
{
class CryptoConfigComponentGUI;

/**
 * Crypto Config Module widget, dynamically generated from CryptoConfig
 * It's a simple QWidget so that it can be embedded into a dialog or into a KCModule.
 */
class KLEO_EXPORT CryptoConfigModule : public KPageWidget
{
    Q_OBJECT
public:
    enum Layout { TabbedLayout, IconListLayout, LinearizedLayout };
    explicit CryptoConfigModule(QGpgME::CryptoConfig *config, QWidget *parent = nullptr);
    explicit CryptoConfigModule(QGpgME::CryptoConfig *config, Layout layout, QWidget *parent = nullptr);

    bool hasError() const;

    void save();
    void reset(); // i.e. reload current settings, discarding user input
    void defaults();
    void cancel();

Q_SIGNALS:
    void changed();

private:
    void init(Layout layout);
    static QStringList sortComponentList(const QStringList &components);

public:
    static QStringList sortGroupList(const QString &moduleName, const QStringList &groups);

private:
    QGpgME::CryptoConfig *mConfig = nullptr;
    QList<CryptoConfigComponentGUI *> mComponentGUIs;
};

}

