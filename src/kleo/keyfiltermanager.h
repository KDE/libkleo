/*
    keyfiltermanager.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"
#include <QObject>

#include <libkleo/keyfilter.h>

#include <memory>
#include <vector>

namespace GpgME
{
class Key;
}

class QAbstractItemModel;
class QModelIndex;
class QFont;
class QColor;
class QIcon;

namespace Kleo
{

class KLEO_EXPORT KeyFilterManager : public QObject
{
    Q_OBJECT
public:
    enum ModelRoles {
        FilterIdRole = Qt::UserRole,
        FilterMatchContextsRole,
    };

protected:
    explicit KeyFilterManager(QObject *parent = nullptr);
    ~KeyFilterManager();

public:
    static KeyFilterManager *instance();

    const std::shared_ptr<KeyFilter> &filterMatching(const GpgME::Key &key, KeyFilter::MatchContexts contexts) const;
    std::vector<std::shared_ptr<KeyFilter>> filtersMatching(const GpgME::Key &key, KeyFilter::MatchContexts contexts) const;

    QAbstractItemModel *model() const;

    const std::shared_ptr<KeyFilter> &keyFilterByID(const QString &id) const;
    const std::shared_ptr<KeyFilter> &fromModelIndex(const QModelIndex &mi) const;
    QModelIndex toModelIndex(const std::shared_ptr<KeyFilter> &kf) const;

    void reload();

    QFont font(const GpgME::Key &key, const QFont &baseFont) const;
    QColor bgColor(const GpgME::Key &key) const;
    QColor fgColor(const GpgME::Key &key) const;
    QIcon icon(const GpgME::Key &key) const;

    class Private;
private:
    Private *d;
    static KeyFilterManager *mSelf;
};

}

