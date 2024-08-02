/*
    kleo/docaction.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Andre Heinecke <aheinecke@g10code.com>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "docaction.h"

#include <libkleo_debug.h>

#include <QCoreApplication>
#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QString>

using namespace Kleo;

class Kleo::DocAction::Private
{
public:
    explicit Private(const QString &filename, const QUrl &url, const QString &pathHint);
    ~Private() = default;

    QString path;
    bool isEnabled = false;
    QUrl url;
};

DocAction::Private::Private(const QString &filename, const QUrl &url, const QString &pathHint)
{
    QString tmp = pathHint;
    if (!tmp.startsWith(QLatin1Char('/'))) {
        tmp.prepend(QLatin1Char('/'));
    }
    QDir datadir(QCoreApplication::applicationDirPath() + (pathHint.isNull() ? QStringLiteral("/../share/kleopatra") : tmp));

    path = datadir.filePath(filename);
    QFileInfo fi(path);
    isEnabled = fi.exists();
    if (!isEnabled) {
        this->url = url;
        isEnabled = url.isValid();
    }
}

DocAction::DocAction(const QIcon &icon, const QString &text, const QString &filename, const QString &pathHint, const QUrl &url, QObject *parent)
    : QAction(icon, text, parent)
    , d(new Private(filename, url, pathHint))
{
    setVisible(d->isEnabled);
    setEnabled(d->isEnabled);
    connect(this, &QAction::triggered, this, [this]() {
        if (d->isEnabled) {
            qCDebug(LIBKLEO_LOG) << "Opening:" << (d->url.isValid() ? d->url.toString() : d->path);
            QDesktopServices::openUrl(d->url.isValid() ? d->url : QUrl::fromLocalFile(d->path));
        }
    });
}

DocAction::~DocAction() = default;

#include "moc_docaction.cpp"
