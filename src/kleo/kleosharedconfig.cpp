// This file is part of Kleopatra, the KDE keymanager
// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Carl Schwan <carl.schwan@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include "kleosharedconfig.h"
#include <utils/gnupg.h>

namespace Kleo
{
namespace SharedConfig
{

KSharedConfig::Ptr openConfig()
{
    const auto fileName = KConfig::mainConfigName();

    // Read config from $GNUPGHOME/kleopatra/kleopatrarc
    auto config = KSharedConfig::openConfig(Kleo::gnupgHomeDirectory() + QStringLiteral("/kleopatra/") + fileName);
    qWarning() << Kleo::gnupgHomeDirectory() + QStringLiteral("/kleopatra/") + fileName;

    // legacy: Read fallback config from ~/.config/kleopatrarc
    config->addConfigSources({QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation) + QLatin1Char('/') + fileName});

    return config;
}

}
}
