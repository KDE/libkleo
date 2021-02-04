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

class KeyGroup::Private
{
public:
    explicit Private(const QString &id, const QString &name, const std::vector<Key> &keys, Source source);

    QString id;
    QString name;
    Keys keys;
    Source source;
};

KeyGroup::Private::Private(const QString &id, const QString &name, const std::vector<Key> &keys, Source source)
    : id(id)
    , name(name)
    , keys(keys.cbegin(), keys.cend())
    , source(source)
{
}

KeyGroup::KeyGroup()
    : KeyGroup(QString(), QString(), {}, UnknownSource)
{
}

KeyGroup::~KeyGroup() = default;

KeyGroup::KeyGroup(const QString &id, const QString &name, const std::vector<Key> &keys, Source source)
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
    return !d || d->id.isEmpty();
}

QString KeyGroup::id() const
{
    return d ? d->id : QString();
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
