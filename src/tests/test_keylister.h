/*
    test_keylister.h

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-only
*/

#pragma once

#include "ui/keylistview.h"

namespace GpgME
{
class Key;
class KeyListResult;
}

class CertListView : public Kleo::KeyListView
{
    Q_OBJECT
public:
    explicit CertListView(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~CertListView();

public Q_SLOTS:
    void slotResult(const GpgME::KeyListResult &result);
    void slotStart();
};

