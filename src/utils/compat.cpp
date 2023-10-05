/*
    utils/compat.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "compat.h"

#include <QGpgME/CryptoConfig>

#include <gpgme++/key.h>

using namespace QGpgME;

QGpgME::CryptoConfigEntry *Kleo::getCryptoConfigEntry(const CryptoConfig *config, const char *componentName, const char *entryName)
{
    if (!config) {
        return nullptr;
    }
    return config->entry(QString::fromLatin1(componentName), QString::fromLatin1(entryName));
}
