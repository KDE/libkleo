/*
    kleo/docaction.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Andre Heinecke <aheinecke@g10code.com>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QAction>

#include <memory>

class QIcon;
class QString;

namespace Kleo
{
/**
    An action for custom documentation which is opened
    by file. This can be used for PDF documents like the
    GnuPG manual.

    The action is disabled and invisible if the corresponding
    file cannout be found at creation. Otherwise triggered
    calls QDesktopServicesOpenURL on the file.
*/
class KLEO_EXPORT DocAction : public QAction
{
    Q_OBJECT

public:
    /* Create a DocAction with icon, text and file name of the document
     *
     * @a filename The name of the documentation file.
     * @a pathHint A path relative to QCoreApplication::applicationDirPath() to look for the file.
     *
     * */
    explicit DocAction(const QIcon &icon, const QString &text, const QString &filename, const QString &pathHint = QString(), QObject *parent = nullptr);

    ~DocAction() override;

    DocAction(const QString &, QObject *parent) = delete;
    DocAction(QObject *parent) = delete;

private:
    class Private;
    std::unique_ptr<Private> d;
};

} // namespace Kleo
