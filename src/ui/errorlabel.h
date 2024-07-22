/*
    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QLabel>

namespace Kleo
{

class KLEO_EXPORT ErrorLabel : public QLabel
{
    Q_OBJECT
public:
    explicit ErrorLabel(QWidget *parent = nullptr);
    ~ErrorLabel() override;
};

}
