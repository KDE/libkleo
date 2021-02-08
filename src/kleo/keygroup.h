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

#include <Libkleo/Predicates>

#include <memory>
#include <set>
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
    typedef int32_t Id;
    typedef std::set<GpgME::Key, _detail::ByFingerprint<std::less>> Keys;

    enum Source {
        UnknownSource,
        ApplicationConfig,
        GnuPGConfig,
        Tags
    };

    KeyGroup();
    ~KeyGroup();

    explicit KeyGroup(Id id, const QString &name, const std::vector<GpgME::Key> &keys, Source source);

    KeyGroup(const KeyGroup &other);
    KeyGroup &operator=(const KeyGroup &other);

    KeyGroup(KeyGroup &&other);
    KeyGroup &operator=(KeyGroup &&other);

    bool isNull() const;

    Id id() const;
    QString name() const;
    const Keys &keys() const;
    Source source() const;

    void setConfigName(const QString &configName);
    QString configName() const;

    void setIsImmutable(bool isImmutable);
    bool isImmutable() const;

    bool insert(const GpgME::Key &key);
    bool erase(const GpgME::Key &key);

private:
    class Private;
    std::unique_ptr<Private> d;
};

}

#endif // LIBKLEO_KEYGROUP_H
