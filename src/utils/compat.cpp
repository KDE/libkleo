/*
    utils/compat.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "compat.h"

#include <QGpgME/CryptoConfig>

#include <gpgme++/gpgmepp_version.h>
#if GPGMEPP_VERSION >= 0x11000 // 1.16.0
# define CRYPTOCONFIG_HAS_GROUPLESS_ENTRY_OVERLOAD
#endif

using namespace QGpgME;

QGpgME::CryptoConfigEntry *Kleo::getCryptoConfigEntry(const CryptoConfig *config, const char *componentName, const char *entryName)
{
#ifdef CRYPTOCONFIG_HAS_GROUPLESS_ENTRY_OVERLOAD
    return config->entry(QString::fromLatin1(componentName), QString::fromLatin1(entryName));
#else
    const CryptoConfigComponent *const comp = config->component(QString::fromLatin1(componentName));
    const QStringList groupNames = comp->groupList();
    for (const auto &groupName : groupNames) {
        const CryptoConfigGroup *const group = comp ? comp->group(groupName) : nullptr;
        if (CryptoConfigEntry *const entry = group->entry(QString::fromLatin1(entryName))) {
            return entry;
        }
    }
    return nullptr;
#endif
}
