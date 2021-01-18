/*
    autotests/flatkeylistmodeltest.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "abstractkeylistmodeltest.h"

#include "models/keylistmodel.h"

#include <QTest>

using namespace Kleo;

class FlatKeyListModelTest: public AbstractKeyListModelTest
{
    Q_OBJECT

private:
    AbstractKeyListModel *createModel() override
    {
        return AbstractKeyListModel::createFlatKeyListModel(this);
    }
};

QTEST_MAIN(FlatKeyListModelTest)
#include "flatkeylistmodeltest.moc"
