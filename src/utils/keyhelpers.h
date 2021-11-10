/*
    utils/keyhelpers.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QStringList>

#include <algorithm>

namespace Kleo
{

template<typename KeyContainer>
QStringList getFingerprints(const KeyContainer &keys)
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
