/*
    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

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
class KeyGroup;

class KLEO_EXPORT KeyGroupConfig
{
public:
    explicit KeyGroupConfig(const QString &filename);
    ~KeyGroupConfig();

    std::vector<KeyGroup> readGroups() const;

    void writeGroups(const std::vector<KeyGroup> &groups);

    KeyGroup writeGroup(const KeyGroup &group);

    bool removeGroup(const KeyGroup &group);

private:
    class Private;
    std::unique_ptr<Private> const d;
};

}
