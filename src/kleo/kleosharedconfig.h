// This file is part of Kleopatra, the KDE keymanager
// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Carl Schwan <carl.schwan@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "kleo_export.h"
#include <KSharedConfig>

namespace Kleo
{
namespace SharedConfig
{
KSharedConfig::Ptr KLEO_EXPORT openConfig();
};

} // end namespace Kleo
