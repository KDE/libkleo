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

#include <QSet>
#include <QTest>

using namespace Kleo;
using namespace GpgME;

Q_DECLARE_METATYPE(KeyGroup)

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

KeyGroup createGroup(const QString &name,
                     const std::vector<Key> &keys = std::vector<Key>(),
                     KeyGroup::Source source = KeyGroup::ApplicationConfig,
                     const QString &configName = QString())
{
    const KeyGroup::Id groupId = (source == KeyGroup::ApplicationConfig) ?
                                 (configName.isEmpty() ? name : configName) :
                                 name;
    KeyGroup g(groupId, name, keys, source);
    return g;
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
        createGroup("test1")
    };
    model->setGroups(groups);
    QCOMPARE( model->rowCount(), 1 );
    QVERIFY( model->index(groups[0]).isValid() );

    const std::vector<KeyGroup> otherGroups = {
        createGroup("test2"),
        createGroup("test3")
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
    const KeyGroup group = createGroup(QStringLiteral("test"), {key});

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
        createGroup("test", {key}, KeyGroup::UnknownSource),
        createGroup("test", {key}, KeyGroup::GnuPGConfig),
        createGroup("test", {key}, KeyGroup::ApplicationConfig, "test"),
        createGroup("test", {key}, KeyGroup::ApplicationConfig, "otherConfigName")
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
        createGroup("test", {key}, KeyGroup::UnknownSource),
        createGroup("test", {key}, KeyGroup::GnuPGConfig),
        createGroup("test", {key}, KeyGroup::ApplicationConfig, "test"),
        createGroup("test", {key}, KeyGroup::ApplicationConfig, "otherConfigName")
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

void AbstractKeyListModelTest::testAddGroup()
{
    QScopedPointer<AbstractKeyListModel> model(createModel());

    {
        const QModelIndex resultIndex = model->addGroup(KeyGroup());
        QVERIFY( !resultIndex.isValid() );
        QCOMPARE( model->rowCount(), 0 );
    }

    {
        const KeyGroup group = createGroup(QStringLiteral("test"));
        const QModelIndex resultIndex = model->addGroup(group);
        QVERIFY( resultIndex.isValid() );
        QCOMPARE( resultIndex.row(), 0 );
        QCOMPARE( resultIndex.column(), 0 );
        QVERIFY( !resultIndex.parent().isValid() );
        QCOMPARE( model->rowCount(), 1 );
        const KeyGroup groupInModel = model->group(model->index(0, 0));
        QVERIFY( !groupInModel.isNull() );
        QCOMPARE( groupInModel.id(), group.id() );
        QCOMPARE( groupInModel.source(), group.source() );
        QCOMPARE( groupInModel.name(), group.name() );
        QCOMPARE( groupInModel.keys().size(), group.keys().size() );
    }
}

void AbstractKeyListModelTest::testSetData()
{
    QScopedPointer<AbstractKeyListModel> model(createModel());

    const Key key = createTestKey("test@example.net");
    const KeyGroup group = createGroup(QStringLiteral("test"));
    model->setKeys({key});
    model->setGroups({group});
    const KeyGroup updatedGroup = createGroup(QStringLiteral("updated"), {key});
    QVERIFY( !model->setData(QModelIndex(), QVariant::fromValue(updatedGroup)) );
    QVERIFY( !model->setData(model->index(key), QVariant::fromValue(updatedGroup)) );

    const QModelIndex groupIndex = model->index(group);
    QVERIFY( model->setData(groupIndex, QVariant::fromValue(updatedGroup)) );
    const KeyGroup groupInModel = model->group(groupIndex);
    QVERIFY( !groupInModel.isNull() );
    QCOMPARE( groupInModel.name(), updatedGroup.name() );
    QCOMPARE( groupInModel.keys().size(), updatedGroup.keys().size() );
}

void AbstractKeyListModelTest::testRemoveGroup()
{
    QScopedPointer<AbstractKeyListModel> model(createModel());

    const KeyGroup group = createGroup(QStringLiteral("test"));
    model->setGroups({group});

    {
        const bool result = model->removeGroup(KeyGroup());
        QVERIFY( !result );
        QCOMPARE( model->rowCount(), 1 );
    }

    {
        const KeyGroup otherGroup = createGroup(QStringLiteral("test2"));

        const bool result = model->removeGroup(otherGroup);
        QVERIFY( !result );
        QCOMPARE( model->rowCount(), 1 );
    }

    {
        const bool result = model->removeGroup(group);
        QVERIFY( result );
        QCOMPARE( model->rowCount(), 0 );
    }
}

void AbstractKeyListModelTest::testClear()
{
    QScopedPointer<AbstractKeyListModel> model(createModel());

    model->setGroups({
        createGroup("test")
    });

    model->clear(AbstractKeyListModel::Keys);
    QCOMPARE( model->rowCount(), 1 );

    model->clear(AbstractKeyListModel::Groups);
    QCOMPARE( model->rowCount(), 0 );
}
