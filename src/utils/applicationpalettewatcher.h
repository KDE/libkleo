/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2025 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QObject>

class KLEO_EXPORT ApplicationPaletteWatcher : public QObject
{
    Q_OBJECT
public:
    explicit ApplicationPaletteWatcher(QObject *parent = nullptr);
    ~ApplicationPaletteWatcher() override;

Q_SIGNALS:
    void paletteChanged();

private:
    bool eventFilter(QObject *obj, QEvent *event) override;
};
