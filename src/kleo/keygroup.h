/*
    kleo/keygroup.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifndef LIBKLEO_KEYGROUP_H
#define LIBKLEO_KEYGROUP_H

#include "kleo_export.h"

#include <memory>
#include <vector>

class QString;

namespace GpgME
{
class Key;
}

namespace Kleo
{

class KLEO_EXPORT KeyGroup
{
public:
    KeyGroup();
    ~KeyGroup();

    explicit KeyGroup(const QString &name, const std::vector<GpgME::Key> &keys);

    KeyGroup(const KeyGroup &other);
    KeyGroup &operator=(const KeyGroup &other);

    KeyGroup(KeyGroup &&other);
    KeyGroup &operator=(KeyGroup &&other);

    bool isNull() const;

    QString name() const;

    const std::vector<GpgME::Key> &keys() const;

private:
    class Private;
    std::unique_ptr<Private> d;
};

}

#endif // LIBKLEO_KEYGROUP_H
