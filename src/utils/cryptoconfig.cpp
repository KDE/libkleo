/*
    utils/cryptoconfig.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "cryptoconfig.h"
#include "cryptoconfig_p.h"

#include "utils/compat.h"

#include <QGpgME/CryptoConfig>
#include <QGpgME/Protocol>

#include <unordered_map>

using namespace QGpgME;

static std::unordered_map<std::string, std::unordered_map<std::string, QString>> fakeCryptoConfigValues;

QString Kleo::getCryptoConfigStringValue(const char *componentName, const char *entryName)
{
    if (!fakeCryptoConfigValues.empty()) {
        const auto componentIt = fakeCryptoConfigValues.find(componentName);
        if (componentIt != std::end(fakeCryptoConfigValues)) {
            const auto entryIt = componentIt->second.find(entryName);
            if (entryIt != std::end(componentIt->second)) {
                return entryIt->second;
            }
        }
    }

    const CryptoConfig *const config = cryptoConfig();
    if (!config) {
        return {};
    }
    const CryptoConfigEntry *const entry = getCryptoConfigEntry(config, "gpg", "compliance");
    if (!entry || entry->argType() != CryptoConfigEntry::ArgType_String) {
        return QString();
    }
    return entry->stringValue();
}

void Kleo::Private::setFakeCryptoConfigStringValue(const std::string &componentName, const std::string &entryName, const QString &fakeValue)
{
    fakeCryptoConfigValues[componentName][entryName] = fakeValue;
}

void Kleo::Private::clearFakeCryptoConfigStringValue(const std::string &componentName, const std::string &entryName)
{
    auto &entryMap = fakeCryptoConfigValues[componentName];
    entryMap.erase(entryName);
    if (entryMap.empty()) {
        fakeCryptoConfigValues.erase(componentName);
    }
}
