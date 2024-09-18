/* -*- mode: c++; c-basic-offset:4 -*-
    ui/filenamerequester.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QDir>
#include <QWidget>

namespace Kleo
{

class KLEO_EXPORT FileNameRequester : public QWidget
{
    Q_OBJECT
    Q_PROPERTY(QString fileName READ fileName WRITE setFileName)
    Q_PROPERTY(bool existingOnly READ existingOnly WRITE setExistingOnly)
public:
    explicit FileNameRequester(QWidget *parent = nullptr);
    explicit FileNameRequester(QDir::Filters filter, QWidget *parent = nullptr);
    ~FileNameRequester() override;

    void setFileName(const QString &name);
    QString fileName() const;

    void setExistingOnly(bool on);
    bool existingOnly() const;

    void setFilter(QDir::Filters f);
    QDir::Filters filter() const;

    void setNameFilter(const QString &nameFilter);
    QString nameFilter() const;

    void setAccessibleNameOfLineEdit(const QString &name);
    void setButtonHint(const QString &text);

Q_SIGNALS:
    void fileNameChanged(const QString &filename);

protected:
    bool event(QEvent *event) override;

private:
    virtual QString requestFileName();

private:
    class FileNameRequesterPrivate;
    std::unique_ptr<FileNameRequesterPrivate> const d;
};

}
