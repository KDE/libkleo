/*
    utils/cryptoconfig_p.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <string>

class QString;

namespace Kleo
{

namespace Private
{

void setFakeCryptoConfigStringValue(const std::string &componentName, const std::string &entryName, const QString &fakeValue);
void clearFakeCryptoConfigStringValue(const std::string &componentName, const std::string &entryName);

}

}
