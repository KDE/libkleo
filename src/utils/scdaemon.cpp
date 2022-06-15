/*
    utils/scdaemon.cpp

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "scdaemon.h"

#include "utils/assuan.h"
#include "utils/hex.h"
#include "utils/stringutils.h"

#include <libkleo_debug.h>

#if __has_include(<QGpgME/Debug>)
#include <QGpgME/Debug>
#endif

#include <gpgme++/context.h>

using namespace Kleo;
using namespace GpgME;

std::vector<std::string> Kleo::SCDaemon::getReaders(Error &err)
{
    std::vector<std::string> result;

    auto c = Context::createForEngine(AssuanEngine, &err);
    if (err) {
        qCDebug(LIBKLEO_LOG) << "Creating context for Assuan engine failed:" << err;
        return result;
    }

    auto assuanContext = std::shared_ptr<Context>(c.release());
    const std::string command = "SCD GETINFO reader_list";
    const auto readers = Assuan::sendDataCommand(assuanContext, command.c_str(), err);
    if (err) {
        return result;
    }

    result = split(readers, '\n');
    // remove empty entries; in particular, the last entry
    result.erase(std::remove_if(std::begin(result), std::end(result), std::mem_fn(&std::string::empty)), std::end(result));

    return result;
}
