/*
    utils/cryptoconfig.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "cryptoconfig.h"
#include "cryptoconfig_p.h"

#include "utils/compat.h"

#include <QGpgME/CryptoConfig>
#include <QGpgME/Protocol>

#include <unordered_map>

using namespace QGpgME;

static std::unordered_map<std::string, std::unordered_map<std::string, int>> fakeCryptoConfigIntValues;
static std::unordered_map<std::string, std::unordered_map<std::string, QString>> fakeCryptoConfigStringValues;

int Kleo::getCryptoConfigIntValue(const char *componentName, const char *entryName, int defaultValue)
{
    if (!fakeCryptoConfigIntValues.empty()) {
        const auto componentIt = fakeCryptoConfigIntValues.find(componentName);
        if (componentIt != std::end(fakeCryptoConfigIntValues)) {
            const auto entryIt = componentIt->second.find(entryName);
            if (entryIt != std::end(componentIt->second)) {
                return entryIt->second;
            }
        }
    }

    const CryptoConfig *const config = cryptoConfig();
    if (!config) {
        return defaultValue;
    }
    const CryptoConfigEntry *const entry = getCryptoConfigEntry(config, componentName, entryName);
    if (entry && entry->argType() == CryptoConfigEntry::ArgType_Int) {
        return entry->intValue();
    }
    return defaultValue;
}

QString Kleo::getCryptoConfigStringValue(const char *componentName, const char *entryName)
{
    if (!fakeCryptoConfigStringValues.empty()) {
        const auto componentIt = fakeCryptoConfigStringValues.find(componentName);
        if (componentIt != std::end(fakeCryptoConfigStringValues)) {
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
    const CryptoConfigEntry *const entry = getCryptoConfigEntry(config, componentName, entryName);
    if (entry && entry->argType() == CryptoConfigEntry::ArgType_String) {
        return entry->stringValue();
    }
    return {};
}

QList<QUrl> Kleo::getCryptoConfigUrlList(const char *componentName, const char *entryName)
{
    const CryptoConfig *const config = cryptoConfig();
    if (!config) {
        return {};
    }
    const CryptoConfigEntry *const entry = getCryptoConfigEntry(config, componentName, entryName);
    if (entry && entry->isList() && (entry->argType() == CryptoConfigEntry::ArgType_LDAPURL || entry->argType() == CryptoConfigEntry::ArgType_Path)) {
        return entry->urlValueList();
    }
    return {};
}

void Kleo::Private::setFakeCryptoConfigIntValue(const std::string &componentName, const std::string &entryName, int fakeValue)
{
    fakeCryptoConfigIntValues[componentName][entryName] = fakeValue;
}

void Kleo::Private::clearFakeCryptoConfigIntValue(const std::string &componentName, const std::string &entryName)
{
    auto &entryMap = fakeCryptoConfigIntValues[componentName];
    entryMap.erase(entryName);
    if (entryMap.empty()) {
        fakeCryptoConfigIntValues.erase(componentName);
    }
}

void Kleo::Private::setFakeCryptoConfigStringValue(const std::string &componentName, const std::string &entryName, const QString &fakeValue)
{
    fakeCryptoConfigStringValues[componentName][entryName] = fakeValue;
}

void Kleo::Private::clearFakeCryptoConfigStringValue(const std::string &componentName, const std::string &entryName)
{
    auto &entryMap = fakeCryptoConfigStringValues[componentName];
    entryMap.erase(entryName);
    if (entryMap.empty()) {
        fakeCryptoConfigStringValues.erase(componentName);
    }
}
