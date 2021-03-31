/* -*- mode: c++; c-basic-offset:4 -*-
    filesystemwatcher.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QObject>

#include <kleo_export.h>

class QString;
#include <QStringList>

namespace Kleo
{

class KLEO_EXPORT FileSystemWatcher : public QObject
{
    Q_OBJECT
public:
    explicit FileSystemWatcher(QObject *parent = nullptr);
    explicit FileSystemWatcher(const QStringList &paths, QObject *parent = nullptr);
    ~FileSystemWatcher();

    void setDelay(int ms);
    int delay() const;

    void setEnabled(bool enable);
    bool isEnabled() const;

    void addPaths(const QStringList &paths);
    void addPath(const QString &path);

    void blacklistFiles(const QStringList &patterns);
    void whitelistFiles(const QStringList &patterns);

    QStringList files() const;
    void removePaths(const QStringList &path);
    void removePath(const QString &path);

Q_SIGNALS:
    void directoryChanged(const QString &path);
    void fileChanged(const QString &path);
    void triggered();

private:
    class Private;
    QScopedPointer<Private> const d;
};
}

