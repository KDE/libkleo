/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "filenamerequester.h"

#include <KLocalizedString>

#include <QCompleter>
#include <QEvent>
#include <QFileDialog>
#include <QFileSystemModel>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QString>
#include <QToolButton>

using namespace Kleo;

class Q_DECL_HIDDEN FileNameRequester::FileNameRequesterPrivate
{
    friend class ::Kleo::FileNameRequester;
    FileNameRequester *const q;

public:
    explicit FileNameRequesterPrivate(FileNameRequester *qq);
    ~FileNameRequesterPrivate();

private:
    void slotButtonClicked();

private:
#ifndef QT_NO_DIRMODEL
    QFileSystemModel dirmodel;
    QCompleter completer;
#else
    QDir::Filters filter;
#endif

    QLineEdit lineedit;
    QToolButton button;
    QHBoxLayout hlay;

    QString nameFilter;
    bool existingOnly;
};

FileNameRequester::FileNameRequesterPrivate::FileNameRequesterPrivate(FileNameRequester *qq)
    : q(qq)
    ,
#ifndef QT_NO_DIRMODEL
    dirmodel()
    , completer(&dirmodel)
    ,
#else
    filter()
    ,
#endif
    lineedit(q)
    , button(q)
    , hlay(q)
    , nameFilter()
    , existingOnly(true)
{
#ifndef QT_NO_DIRMODEL
    dirmodel.setObjectName(QLatin1StringView("dirmodel"));
    completer.setObjectName(QLatin1StringView("completer"));
#endif
    lineedit.setObjectName(QLatin1StringView("lineedit"));
    button.setObjectName(QLatin1StringView("button"));
    hlay.setObjectName(QLatin1StringView("hlay"));

    button.setIcon(QIcon::fromTheme(QStringLiteral("document-open")));
    button.setToolTip(i18nc("@info:tooltip", "Open file dialog"));
    button.setAccessibleName(i18n("Open file dialog"));
#ifndef QT_NO_DIRMODEL
    lineedit.setCompleter(&completer);
#endif
    lineedit.setClearButtonEnabled(true);
    hlay.setContentsMargins(0, 0, 0, 0);
    hlay.addWidget(&lineedit);
    hlay.addWidget(&button);
    q->setFocusPolicy(lineedit.focusPolicy());
    q->setFocusProxy(&lineedit);

    connect(&button, &QToolButton::clicked, q, [this]() {
        slotButtonClicked();
    });
    connect(&lineedit, &QLineEdit::textChanged, q, &FileNameRequester::fileNameChanged);
}

FileNameRequester::FileNameRequesterPrivate::~FileNameRequesterPrivate()
{
}

FileNameRequester::FileNameRequester(QWidget *p)
    : QWidget(p)
    , d(new FileNameRequesterPrivate(this))
{
}

FileNameRequester::FileNameRequester(QDir::Filters f, QWidget *p)
    : QWidget(p)
    , d(new FileNameRequesterPrivate(this))
{
#ifndef QT_NO_DIRMODEL
    d->dirmodel.setFilter(f);
#else
    d->filter = f;
#endif
}

FileNameRequester::~FileNameRequester() = default;

void FileNameRequester::setFileName(const QString &file)
{
    d->lineedit.setText(file);
}

QString FileNameRequester::fileName() const
{
    return d->lineedit.text();
}

void FileNameRequester::setExistingOnly(bool on)
{
    d->existingOnly = on;
}

bool FileNameRequester::existingOnly() const
{
    return d->existingOnly;
}

void FileNameRequester::setFilter(QDir::Filters f)
{
#ifndef QT_NO_DIRMODEL
    d->dirmodel.setFilter(f);
#else
    d->filter = f;
#endif
}

QDir::Filters FileNameRequester::filter() const
{
#ifndef QT_NO_DIRMODEL
    return d->dirmodel.filter();
#else
    return d->filter;
#endif
}

void FileNameRequester::setNameFilter(const QString &nameFilter)
{
    d->nameFilter = nameFilter;
}

QString FileNameRequester::nameFilter() const
{
    return d->nameFilter;
}

void FileNameRequester::setAccessibleNameOfLineEdit(const QString &name)
{
    d->lineedit.setAccessibleName(name);
}

void FileNameRequester::FileNameRequesterPrivate::slotButtonClicked()
{
    const QString fileName = q->requestFileName();
    if (!fileName.isEmpty()) {
        q->setFileName(fileName);
    }
}

bool FileNameRequester::event(QEvent *e)
{
    if (e->type() == QEvent::ToolTipChange) {
        d->lineedit.setToolTip(toolTip());
    }
    return QWidget::event(e);
}

QString FileNameRequester::requestFileName()
{
#ifndef QT_NO_FILEDIALOG
    const QDir::Filters filters = filter();
    if ((filters & QDir::Dirs) && !(filters & QDir::Files)) {
        return QFileDialog::getExistingDirectory(this);
    } else if (d->existingOnly) {
        return QFileDialog::getOpenFileName(this, QString(), QString(), d->nameFilter);
    } else {
        return QFileDialog::getSaveFileName(this, QString(), fileName(), d->nameFilter);
    }
#else
    return QString();
#endif
}

void FileNameRequester::setButtonHint(const QString &text)
{
    d->button.setToolTip(text);
    d->button.setAccessibleName(text);
}

#include "moc_filenamerequester.cpp"
