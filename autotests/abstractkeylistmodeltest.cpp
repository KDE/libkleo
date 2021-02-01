/*
    autotests/abstractkeylistmodeltest.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "abstractkeylistmodeltest.h"

#include "kleo/keygroup.h"
#include "models/keylistmodel.h"

#include <gpgme++/key.h>

#include <gpgme.h>

#include <QTest>

using namespace Kleo;
using namespace GpgME;

namespace
{
Key createTestKey(const char *uid)
{
    static int count = 0;
    count++;

    gpgme_key_t key;
    gpgme_key_from_uid(&key, uid);
    const QByteArray fingerprint = QByteArray::number(count, 16).rightJustified(40, '0');
    key->fpr = strdup(fingerprint.constData());

    return Key(key, false);
}
}

void AbstractKeyListModelTest::testCreation()
{
    QScopedPointer<AbstractKeyListModel> model(createModel());
    QCOMPARE( model->rowCount(), 0 );
}

void AbstractKeyListModelTest::testSetKeys()
{
    QScopedPointer<AbstractKeyListModel> model(createModel());

    const std::vector<Key> keys = {
        createTestKey("test1@example.net")
    };
    model->setKeys(keys);
    QCOMPARE( model->rowCount(), 1 );
    QVERIFY( model->index(keys[0]).isValid() );

    const std::vector<Key> otherKeys = {
        createTestKey("test2@example.net"),
        createTestKey("test3@example.net")
    };
    model->setKeys(otherKeys);
    QCOMPARE( model->rowCount(), 2 );
    QVERIFY( model->index(otherKeys[0]).isValid() );
    QVERIFY( model->index(otherKeys[1]).isValid() );
    QVERIFY( !model->index(keys[0]).isValid() );
}

void AbstractKeyListModelTest::testSetGroups()
{
    QScopedPointer<AbstractKeyListModel> model(createModel());

    const std::vector<KeyGroup> groups = {
        KeyGroup("test1", "test1", std::vector<Key>(), KeyGroup::UnknownSource)
    };
    model->setGroups(groups);
    QCOMPARE( model->rowCount(), 1 );
    QVERIFY( model->index(groups[0]).isValid() );

    const std::vector<KeyGroup> otherGroups = {
        KeyGroup("test2", "test2", std::vector<Key>(), KeyGroup::UnknownSource),
        KeyGroup("test3", "test3", std::vector<Key>(), KeyGroup::UnknownSource)
    };
    model->setGroups(otherGroups);
    QCOMPARE( model->rowCount(), 2 );
    QVERIFY( model->index(otherGroups[0]).isValid() );
    QVERIFY( model->index(otherGroups[1]).isValid() );
    QVERIFY( !model->index(groups[0]).isValid() );
}

void AbstractKeyListModelTest::testKeys()
{
    QScopedPointer<AbstractKeyListModel> model(createModel());

    const Key key = createTestKey("test@example.net");
    const KeyGroup group("test", "test", {key}, KeyGroup::UnknownSource);

    model->setKeys({key});
    model->setGroups({group});

    QCOMPARE( model->rowCount(), 2 );

    const QModelIndex keyIndex = model->index(key);
    QVERIFY( keyIndex.isValid() );
    const QModelIndex groupIndex = model->index(group);
    QVERIFY( groupIndex.isValid() );

    {
        const auto keys = model->keys({});
        QCOMPARE( keys.size(), 0 );
    }

    {
        const auto keys = model->keys({keyIndex});
        QCOMPARE( keys.size(), 1 );
        QCOMPARE( keys[0].userID(0).addrSpec(), UserID::addrSpecFromString("test@example.net") );
    }

    {
        // duplicate keys are removed from result
        const auto keys = model->keys({keyIndex, keyIndex});
        QCOMPARE( keys.size(), 1 );
        QCOMPARE( keys[0].userID(0).addrSpec(), UserID::addrSpecFromString("test@example.net") );
    }

    {
        // null keys are removed from result
        const auto keys = model->keys({groupIndex});
        QCOMPARE( keys.size(), 0 );
    }
}

void AbstractKeyListModelTest::testIndex()
{
    QScopedPointer<AbstractKeyListModel> model(createModel());

    const Key key = createTestKey("test@example.net");
    const std::vector<KeyGroup> groups = {
        KeyGroup("test", "test", {key}, KeyGroup::UnknownSource),
        KeyGroup("test", "test", {key}, KeyGroup::GnuPGConfig),
        KeyGroup("test", "test", {key}, KeyGroup::ApplicationConfig),
        KeyGroup("otherId", "test", {key}, KeyGroup::UnknownSource)
    };

    model->setKeys({key});
    model->setGroups(groups);

    const QModelIndex keyIndex = model->index(0, 0);
    QVERIFY( keyIndex.isValid() );
    QVERIFY( !model->key(keyIndex).isNull() );

    const QModelIndex groupIndex = model->index(1, 0);
    QVERIFY( groupIndex.isValid() );
    QVERIFY( !model->group(groupIndex).isNull() );
}

void AbstractKeyListModelTest::testIndexForGroup()
{
    QScopedPointer<AbstractKeyListModel> model(createModel());

    const Key key = createTestKey("test@example.net");
    const std::vector<KeyGroup> groups = {
        KeyGroup("test", "test", {key}, KeyGroup::UnknownSource),
        KeyGroup("test", "test", {key}, KeyGroup::GnuPGConfig),
        KeyGroup("test", "test", {key}, KeyGroup::ApplicationConfig),
        KeyGroup("otherId", "test", {key}, KeyGroup::UnknownSource)
    };

    model->setKeys({key});
    model->setGroups(groups);

    QSet<int> rows;
    for (const KeyGroup &group : groups) {
        const QModelIndex groupIndex = model->index(group);
        QVERIFY( groupIndex.isValid() );
        rows.insert(groupIndex.row());
    }
    QCOMPARE(rows.size(), 4);
}

void AbstractKeyListModelTest::testClear()
{
    QScopedPointer<AbstractKeyListModel> model(createModel());

    const KeyGroup group("test", "test", std::vector<Key>(), KeyGroup::UnknownSource);
    model->setGroups({group});

    model->clear(AbstractKeyListModel::Keys);
    QCOMPARE( model->rowCount(), 1 );

    model->clear(AbstractKeyListModel::Groups);
    QCOMPARE( model->rowCount(), 0 );
}
