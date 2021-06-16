/*
    ui/directoryserviceswidget.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2001, 2002, 2004 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QWidget>

#include <memory>
#include <vector>

namespace Kleo
{
class KeyserverConfig;

class KLEO_EXPORT DirectoryServicesWidget : public QWidget
{
    Q_OBJECT
public:
    explicit DirectoryServicesWidget(QWidget *parent = nullptr);
    ~DirectoryServicesWidget() override;

    void setKeyservers(const std::vector<KeyserverConfig> &keyservers);
    std::vector<KeyserverConfig> keyservers() const;

    void setReadOnly(bool readOnly);

public Q_SLOTS:
    void clear();

Q_SIGNALS:
    void changed();

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
