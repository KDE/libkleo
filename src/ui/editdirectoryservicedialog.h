/*
    ui/editdirectoryservicedialog.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QDialog>

#include <memory>

#include "kleo_export.h"

namespace Kleo
{
class KeyserverConfig;

class KLEO_EXPORT EditDirectoryServiceDialog : public QDialog
{
    Q_OBJECT
public:
    explicit EditDirectoryServiceDialog(QWidget *parent = nullptr, Qt::WindowFlags f = Qt::WindowFlags());
    ~EditDirectoryServiceDialog() override;

    void setKeyserver(const KeyserverConfig &keyserver);
    KeyserverConfig keyserver() const;

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
