/*
    utils/scdaemon.cpp

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "scdaemon.h"

#include "algorithm.h"
#include "assuan.h"
#include "hex.h"
#include "stringutils.h"

#include <libkleo_debug.h>

#if __has_include(<QGpgME/Debug>)
#include <QGpgME/Debug>
#endif

#include <gpgme++/context.h>

using namespace Kleo;
using namespace GpgME;

std::vector<std::string> Kleo::SCDaemon::getReaders(Error &err)
{
    auto c = Context::createForEngine(AssuanEngine, &err);
    if (err) {
        qCDebug(LIBKLEO_LOG) << "Creating context for Assuan engine failed:" << err;
        return {};
    }

    auto assuanContext = std::shared_ptr<Context>(c.release());
    const std::string command = "SCD GETINFO reader_list";
    const std::string readers = Assuan::sendDataCommand(assuanContext, command.c_str(), err);
    if (err) {
        return {};
    }

    std::vector<std::string_view> tmp = Kleo::split(readers, '\n');
    // remove empty entries; in particular, the last entry
    Kleo::erase_if(tmp, std::mem_fn(&std::string_view::empty));

    return Kleo::toStrings(tmp);
}
