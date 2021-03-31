/* -*- mode: c++; c-basic-offset:4 -*-
    models/keycache_p.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "keycache.h"

namespace GpgME
{
class KeyListResult;
}

namespace Kleo
{

class KeyCache::RefreshKeysJob : public QObject
{
    Q_OBJECT
public:

    explicit RefreshKeysJob(KeyCache *cache, QObject *parent = nullptr);
    ~RefreshKeysJob();

    void start();
    void cancel();

Q_SIGNALS:
    void done(const GpgME::KeyListResult &);
    void canceled();

private:
    class Private;
    friend class Private;
    Private * const d;
    Q_PRIVATE_SLOT(d, void listAllKeysJobDone(GpgME::KeyListResult, std::vector<GpgME::Key>))
};
}

