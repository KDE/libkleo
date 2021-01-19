/*
    autotests/flatkeylistmodeltest.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "kleo/keygroup.h"
#include "models/keylistmodel.h"

#include <gpgme++/key.h>

#include <QTest>

class FlatKeyListModelTest: public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void testCreation();
    void testSetGroups();
    void testClear();
};

using namespace Kleo;
using namespace GpgME;

void FlatKeyListModelTest::testCreation()
{
    QScopedPointer<AbstractKeyListModel> model(AbstractKeyListModel::createFlatKeyListModel(this));
    QCOMPARE( model->rowCount(), 0 );
}

void FlatKeyListModelTest::testSetGroups()
{
    QScopedPointer<AbstractKeyListModel> model(AbstractKeyListModel::createFlatKeyListModel(this));

    const std::vector<KeyGroup> groups = {
        KeyGroup("test1", std::vector<Key>())
    };
    model->setGroups(groups);
    QCOMPARE( model->rowCount(), 1 );
    QVERIFY( model->index(groups[0]).isValid() );

    const std::vector<KeyGroup> otherGroups = {
        KeyGroup("test2", std::vector<Key>()),
        KeyGroup("test3", std::vector<Key>())
    };
    model->setGroups(otherGroups);
    QCOMPARE( model->rowCount(), 2 );
    QVERIFY( model->index(otherGroups[0]).isValid() );
    QVERIFY( model->index(otherGroups[1]).isValid() );
    QVERIFY( !model->index(groups[0]).isValid() );
}

void FlatKeyListModelTest::testClear()
{
    QScopedPointer<AbstractKeyListModel> model(AbstractKeyListModel::createFlatKeyListModel(this));

    const KeyGroup group("test", std::vector<Key>());
    model->setGroups({group});

    model->clear(AbstractKeyListModel::Keys);
    QCOMPARE( model->rowCount(), 1 );

    model->clear(AbstractKeyListModel::Groups);
    QCOMPARE( model->rowCount(), 0 );
}

QTEST_MAIN(FlatKeyListModelTest)
#include "flatkeylistmodeltest.moc"
