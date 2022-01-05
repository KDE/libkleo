/*
    kleo/keygroupimportexport.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "keygroupimportexport.h"

#include "debug.h"
#include "keygroup.h"

#include "models/keycache.h"
#include "utils/keyhelpers.h"
#include "utils/qtstlhelpers.h"

#include <QFile>
#include <QSettings>
#include <QString>

#include "libkleo_debug.h"

using namespace Kleo;
using namespace GpgME;

// use a different, less generic prefix for the config group names than in
// KeyGroupConfig to avoid problems with "Group-*" config groups created by
// other applications; this means that the key groups stored in the normal group
// configuration file cannot be read with the below functions, but that's a good
// thing because the ini files created by KConfig are incompatible with QSettings
static const QString keyGroupNamePrefix = QStringLiteral("KeyGroup-");

namespace
{

QString readString(const QSettings &settings, const QString &key)
{
    return settings.value(key, QString{}).toString();
}

QStringList readStringList(const QSettings &settings, const QString &key)
{
    auto variant = settings.value(key);
    if (!variant.isValid()) {
        return {};
    }
    if ((variant.userType() == QMetaType::QString) && variant.toString().isEmpty()) {
        // interpret empty string value as empty list instead of as list with an empty string
        return {};
    }
    // opportunistically, interpret the value as string list
    return variant.toStringList();
}

void writeString(QSettings &settings, const QString &key, const QString &string)
{
    settings.setValue(key, string);
}

void writeStringList(QSettings &settings, const QString &key, const QStringList &list)
{
    // write empty list as empty string to avoid Qt's "@Invalid()"
    if (list.empty()) {
        writeString(settings, key, {});
    } else {
        settings.setValue(key, list);
    }
}

KeyGroup readGroup(const QSettings &groupsConfig, const QString &groupId)
{
    const auto configGroupPath = keyGroupNamePrefix + groupId + QLatin1Char{'/'};

    const auto groupName = readString(groupsConfig, configGroupPath + QLatin1String{"Name"});
    const auto fingerprints = readStringList(groupsConfig, configGroupPath + QLatin1String{"Keys"});
    const std::vector<Key> groupKeys = KeyCache::instance()->findByFingerprint(toStdStrings(fingerprints));

    KeyGroup g(groupId, groupName, groupKeys, KeyGroup::ApplicationConfig);
    qCDebug(LIBKLEO_LOG) << __func__ << "Read group" << g;

    return g;
}

void writeGroup(QSettings &groupsConfig, const KeyGroup &group)
{
    if (group.isNull()) {
        qCDebug(LIBKLEO_LOG) << __func__ << "Error: group is null";
        return;
    }

    const auto configGroupName = keyGroupNamePrefix + group.id();
    qCDebug(LIBKLEO_LOG) << __func__ << "Writing config group" << configGroupName;
    const auto configGroupPath = configGroupName + QLatin1Char{'/'};
    writeString(groupsConfig, configGroupPath + QLatin1String{"Name"}, group.name());
    writeStringList(groupsConfig, configGroupPath + QLatin1String{"Keys"}, Kleo::getFingerprints(group.keys()));
}

} // namespace

std::vector<KeyGroup> Kleo::readKeyGroups(const QString &filename)
{
    std::vector<KeyGroup> groups;

    if (filename.isEmpty()) {
        return groups;
    }

    if (!QFile::exists(filename)) {
        qCWarning(LIBKLEO_LOG) << __func__ << "File" << filename << "does not exist";
        return groups;
    }

    const QSettings groupsConfig{filename, QSettings::IniFormat};
    const QStringList configGroups = groupsConfig.childGroups();
    for (const QString &configGroupName : configGroups) {
        if (configGroupName.startsWith(keyGroupNamePrefix)) {
            qCDebug(LIBKLEO_LOG) << __func__ << "Reading config group" << configGroupName;
            const QString keyGroupId = configGroupName.mid(keyGroupNamePrefix.size());
            if (keyGroupId.isEmpty()) {
                qCWarning(LIBKLEO_LOG) << __func__ << "Config group" << configGroupName << "has empty group id";
                continue;
            }
            groups.push_back(readGroup(groupsConfig, keyGroupId));
        }
    }

    return groups;
}

Kleo::WriteKeyGroups Kleo::writeKeyGroups(const QString &filename, const std::vector<KeyGroup> &groups)
{
    if (filename.isEmpty()) {
        return WriteKeyGroups::InvalidFilename;
    }

    QSettings groupsConfig{filename, QSettings::IniFormat};
    for (const auto &group : groups) {
        writeGroup(groupsConfig, group);
    }
    // ensure that the data is written to disk before calling status()
    groupsConfig.sync();
    qCDebug(LIBKLEO_LOG) << __func__ << "groupsConfig.status():" << groupsConfig.status();
    return groupsConfig.status() == QSettings::NoError ? WriteKeyGroups::Success : WriteKeyGroups::Error;
}
