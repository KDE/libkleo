/*
    kleo/keygroupconfig.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "keygroupconfig.h"

#include "debug.h"
#include "keygroup.h"

#include "models/keycache.h"
#include "utils/qtstlhelpers.h"

#include <KConfigGroup>
#include <KSharedConfig>

#include <QString>

#include <gpgme++/key.h>

#include "libkleo_debug.h"

using namespace Kleo;
using namespace GpgME;

static const QString groupNamePrefix = QStringLiteral("Group-");

class KeyGroupConfig::Private
{
public:
    explicit Private(const QString &filename);

    std::vector<KeyGroup> readGroups() const;
    KeyGroup writeGroup(const KeyGroup &group);
    bool removeGroup(const KeyGroup &group);

private:
    KeyGroup readGroup(const KSharedConfigPtr &groupsConfig, const QString &groupId) const;

private:
    QString filename;
};

KeyGroupConfig::Private::Private(const QString &filename)
    : filename{filename}
{
    if (filename.isEmpty()) {
        qCWarning(LIBKLEO_LOG) << __func__ << "Warning: name of configuration file is empty";
    }
}

KeyGroup KeyGroupConfig::Private::readGroup(const KSharedConfigPtr &groupsConfig, const QString &groupId) const
{
    const KConfigGroup configGroup = groupsConfig->group(groupNamePrefix + groupId);

    const QString groupName = configGroup.readEntry("Name", QString());
    const auto fingerprints = toStdStrings(configGroup.readEntry("Keys", QStringList()));
    const std::vector<Key> groupKeys = KeyCache::instance()->findByFingerprint(fingerprints);

    // treat group as immutable if any of its entries is immutable
    const QStringList entries = configGroup.keyList();
    const bool isImmutable = configGroup.isImmutable() || std::any_of(entries.begin(), entries.end(),
                                                                        [configGroup] (const QString &entry) {
                                                                            return configGroup.isEntryImmutable(entry);
                                                                        });

    KeyGroup g(groupId, groupName, groupKeys, KeyGroup::ApplicationConfig);
    g.setIsImmutable(isImmutable);
    qCDebug(LIBKLEO_LOG) << "Read group" << g;

    return g;
}

std::vector<KeyGroup> KeyGroupConfig::Private::readGroups() const
{
    std::vector<KeyGroup> groups;

    if (filename.isEmpty()) {
        return groups;
    }

    const KSharedConfigPtr groupsConfig = KSharedConfig::openConfig(filename);
    const QStringList configGroups = groupsConfig->groupList();
    for (const QString &configGroupName : configGroups) {
        qCDebug(LIBKLEO_LOG) << "Reading config group" << configGroupName;
        if (configGroupName.startsWith(groupNamePrefix)) {
            const QString keyGroupId = configGroupName.mid(groupNamePrefix.size());
            if (keyGroupId.isEmpty()) {
                qCWarning(LIBKLEO_LOG) << "Config group" << configGroupName << "has empty group id";
                continue;
            }
            KeyGroup group = readGroup(groupsConfig, keyGroupId);
            groups.push_back(group);
        }
    }

    return groups;
}

namespace
{
auto getFingerprints(const KeyGroup::Keys &keys)
{
    QStringList fingerprints;

    fingerprints.reserve(keys.size());
    std::transform(std::begin(keys), std::end(keys),
                   std::back_inserter(fingerprints),
                   [](const auto &key) {
                       return QString::fromLatin1(key.primaryFingerprint());
                   });

    return fingerprints;
}
}

KeyGroup KeyGroupConfig::Private::writeGroup(const KeyGroup &group)
{
    if (filename.isEmpty()) {
        return {};
    }

    if (group.isNull()) {
        qCDebug(LIBKLEO_LOG) << __func__ << "Error: group is null";
        return group;
    }

    KSharedConfigPtr groupsConfig = KSharedConfig::openConfig(filename);
    KConfigGroup configGroup = groupsConfig->group(groupNamePrefix + group.id());

    qCDebug(LIBKLEO_LOG) << __func__ << "Writing config group" << configGroup.name();
    configGroup.writeEntry("Name", group.name());
    configGroup.writeEntry("Keys", getFingerprints(group.keys()));

    // reread group to ensure that it reflects the saved group in case of immutable entries
    return readGroup(groupsConfig, group.id());
}

bool KeyGroupConfig::Private::removeGroup(const KeyGroup &group)
{
    if (filename.isEmpty()) {
        return false;
    }

    if (group.isNull()) {
        qCDebug(LIBKLEO_LOG) << __func__ << "Error: group is null";
        return false;
    }

    KSharedConfigPtr groupsConfig = KSharedConfig::openConfig(filename);
    KConfigGroup configGroup = groupsConfig->group(groupNamePrefix + group.id());

    qCDebug(LIBKLEO_LOG) << __func__ << "Removing config group" << configGroup.name();
    configGroup.deleteGroup();

    return true;
}

KeyGroupConfig::KeyGroupConfig(const QString &filename)
    : d{std::make_unique<Private>(filename)}
{
}

KeyGroupConfig::~KeyGroupConfig() = default;

std::vector<KeyGroup> KeyGroupConfig::readGroups() const
{
    return d->readGroups();
}

KeyGroup KeyGroupConfig::writeGroup(const KeyGroup &group)
{
    return d->writeGroup(group);
}

void KeyGroupConfig::writeGroups(const std::vector<KeyGroup> &groups)
{
    std::for_each(std::begin(groups), std::end(groups),
                  [this](const auto &group) { d->writeGroup(group); });
}

bool KeyGroupConfig::removeGroup(const KeyGroup &group)
{
    return d->removeGroup(group);
}
