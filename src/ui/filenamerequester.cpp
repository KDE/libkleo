/* -*- mode: c++; c-basic-offset:4 -*-
    ui/filenamerequester.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "filenamerequester.h"

#include <KLineEdit>
#include <KLocalizedString>

#include <QHBoxLayout>
#include <QToolButton>
#include <QCompleter>
#include <QDirModel>
#include <QString>
#include <QFileDialog>
#include <QEvent>

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
    QDirModel  dirmodel;
    QCompleter completer;
#else
    QDir::Filters filter;
#endif

    KLineEdit    lineedit;
    QToolButton  button;
    QHBoxLayout hlay;

    QString nameFilter;
    bool existingOnly;
};

FileNameRequester::FileNameRequesterPrivate::FileNameRequesterPrivate(FileNameRequester *qq)
    : q(qq),
#ifndef QT_NO_DIRMODEL
      dirmodel(),
      completer(&dirmodel),
#else
      filter(),
#endif
      lineedit(q),
      button(q),
      hlay(q),
      nameFilter(),
      existingOnly(true)
{
#ifndef QT_NO_DIRMODEL
    dirmodel.setObjectName(QStringLiteral("dirmodel"));
    completer.setObjectName(QStringLiteral("completer"));
#endif
    lineedit.setObjectName(QStringLiteral("lineedit"));
    button.setObjectName(QStringLiteral("button"));
    hlay.setObjectName(QStringLiteral("hlay"));

    button.setIcon(QIcon::fromTheme(QStringLiteral("document-open")));
    button.setToolTip(i18n("Open file dialog"));
#ifndef QT_NO_DIRMODEL
    lineedit.setCompleter(&completer);
#endif
    lineedit.setClearButtonEnabled(true);
    hlay.setContentsMargins(0, 0, 0, 0);
    hlay.addWidget(&lineedit);
    hlay.addWidget(&button);
    q->setFocusPolicy(lineedit.focusPolicy());
    q->setFocusProxy(&lineedit);

    connect(&button, &QToolButton::clicked, q, [this]() { slotButtonClicked(); });
    connect(&lineedit, &KLineEdit::textChanged, q, &FileNameRequester::fileNameChanged);
}

FileNameRequester::FileNameRequesterPrivate::~FileNameRequesterPrivate() {}

FileNameRequester::FileNameRequester(QWidget *p)
    : QWidget(p), d(new FileNameRequesterPrivate(this))
{

}

FileNameRequester::FileNameRequester(QDir::Filters f, QWidget *p)
    : QWidget(p), d(new FileNameRequesterPrivate(this))
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
        return QFileDialog::getSaveFileName(this, QString(), QString(), d->nameFilter);
    }
#else
    return QString();
#endif
}

#include "moc_filenamerequester.cpp"
