/*
    autotests/abstractkeylistmodeltest.h

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QObject>

namespace Kleo
{
class AbstractKeyListModel;
}

class AbstractKeyListModelTest: public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void testCreation();
    void testSetKeys();
    void testSetGroups();
    void testKeys();
    void testIndex();
    void testIndexForGroup();
    void testAddGroup();
    void testSetData();
    void testRemoveGroup();
    void testClear();

private:
    virtual Kleo::AbstractKeyListModel *createModel() = 0;
};

