/*
    utils/scdaemon.h

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <string>
#include <vector>

namespace GpgME
{
class Error;
}

namespace Kleo
{
/** This namespace collects higher-level functions for retrieving information
 *  from the GnuPG smart card daemon. */
namespace SCDaemon
{

/** Returns the list of available smart card readers. If an error occurred,
 *  then @p err provides details.
 *  The returned strings are mostly useful for configuring the reader to use
 *  via the reader-port option of scdaemon.
 */
KLEO_EXPORT std::vector<std::string> getReaders(GpgME::Error &err);

}
}
