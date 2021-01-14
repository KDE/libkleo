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
    explicit Private(const QString &name, const std::vector<GpgME::Key> &keys);

    QString name;
    std::vector<Key> keys;
};

KeyGroup::Private::Private(const QString &name_, const std::vector<GpgME::Key> &keys_)
    : name(name_)
    , keys(keys_)
{
}

KeyGroup::KeyGroup()
    : KeyGroup(QString(), {})
{
}

KeyGroup::~KeyGroup() = default;

KeyGroup::KeyGroup(const QString &name, const std::vector<GpgME::Key> &keys)
    : d(new Private(name, keys))
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
    return !d || d->name.isEmpty();
}

QString KeyGroup::name() const
{
    return d ? d->name : QString();
}

std::vector<Key> Kleo::KeyGroup::keys() const
{
    return d ? d->keys : std::vector<Key>();
}
