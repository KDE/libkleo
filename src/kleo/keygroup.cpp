/*
    kleo/keygroup.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "keygroup.h"

#include <QString>

#include <gpgme++/key.h>

using namespace Kleo;
using namespace GpgME;

static const KeyGroup::Id nullId = -1;

class KeyGroup::Private
{
public:
    explicit Private(Id id, const QString &name, const std::vector<Key> &keys, Source source);

    Id id;
    QString name;
    QString configName;
    Keys keys;
    Source source;
};

KeyGroup::Private::Private(Id id, const QString &name, const std::vector<Key> &keys, Source source)
    : id(id)
    , name(name)
    , keys(keys.cbegin(), keys.cend())
    , source(source)
{
}

KeyGroup::KeyGroup()
    : KeyGroup(nullId, QString(), {}, UnknownSource)
{
}

KeyGroup::~KeyGroup() = default;

KeyGroup::KeyGroup(Id id, const QString &name, const std::vector<Key> &keys, Source source)
    : d(new Private(id, name, keys, source))
{
}

KeyGroup::KeyGroup(const KeyGroup &other)
    : d(new Private(*other.d))
{
}

KeyGroup &KeyGroup::operator=(const KeyGroup &other)
{
    *d = *other.d;
    return *this;
}

KeyGroup::KeyGroup(KeyGroup &&other) = default;

KeyGroup &KeyGroup::operator=(KeyGroup &&other) = default;

bool KeyGroup::isNull() const
{
    return !d || d->id == nullId;
}

KeyGroup::Id KeyGroup::id() const
{
    return d ? d->id : nullId;
}

QString KeyGroup::name() const
{
    return d ? d->name : QString();
}

const KeyGroup::Keys &KeyGroup::keys() const
{
    static const Keys empty;
    return d ? d->keys : empty;
}

KeyGroup::Source KeyGroup::source() const
{
    return d ? d->source : UnknownSource;
}

void KeyGroup::setConfigName(const QString &configName)
{
    if (d) {
        d->configName = configName;
    }
}

QString KeyGroup::configName() const
{
    return d ? d->configName : QString();
}

bool KeyGroup::insert(const GpgME::Key &key)
{
    if (!d || key.isNull()) {
        return false;
    }
    return d->keys.insert(key).second;
}

bool KeyGroup::erase(const GpgME::Key &key)
{
    if (!d || key.isNull()) {
        return false;
    }
    return d->keys.erase(key) > 0;
}
