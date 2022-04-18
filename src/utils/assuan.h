/*
    utils/assuan.h

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2021, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <memory>
#include <vector>

#include "kleo_export.h"

namespace GpgME
{
class AssuanTransaction;
class Context;
class DefaultAssuanTransaction;
class Error;
}

namespace Kleo
{
/** The Assuan namespace collects functions for communicating with the GnuPG
 *  agent via the Assuan protocol. */
namespace Assuan
{

/** Checks if the GnuPG agent is running and accepts connections. */
KLEO_EXPORT bool agentIsRunning();

/** Sends the Assuan @p command using the @p transaction and the @p assuanContext
 *  to the GnuPG agent and waits for the result. The returned transaction can be used
 *  to retrieve the result.
 *  If an error occurred, then @p err provides details. */
KLEO_EXPORT std::unique_ptr<GpgME::AssuanTransaction> sendCommand(std::shared_ptr<GpgME::Context> &assuanContext,
                                                                  const std::string &command,
                                                                  std::unique_ptr<GpgME::AssuanTransaction> transaction,
                                                                  GpgME::Error &err);

/** Sends the Assuan @p command using a default Assuan transaction and the @p assuanContext
 *  to the GnuPG agent and waits for the result. The returned transaction can be used
 *  to retrieve the result.
 *  If an error occurred, then @p err provides details. */
KLEO_EXPORT std::unique_ptr<GpgME::DefaultAssuanTransaction>
sendCommand(std::shared_ptr<GpgME::Context> &assuanContext, const std::string &command, GpgME::Error &err);

/** Sends the Assuan @p command using a default Assuan transaction and the @p assuanContext
 *  to the GnuPG agent and waits for the result. Returns the data that was sent by
 *  GnuPG agent in response to the @p command.
 *  If an error occurred, then @p err provides details. */
KLEO_EXPORT std::string sendDataCommand(std::shared_ptr<GpgME::Context> assuanContext, const std::string &command, GpgME::Error &err);

/** Sends the Assuan @p command using a default Assuan transaction and the @p assuanContext
 *  to the GnuPG agent and waits for the result. Returns the status lines that were sent by
 *  GnuPG agent in response to the @p command.
 *  If an error occurred, then @p err provides details. */
KLEO_EXPORT std::vector<std::pair<std::string, std::string>>
sendStatusLinesCommand(std::shared_ptr<GpgME::Context> assuanContext, const std::string &command, GpgME::Error &err);

/** Sends the Assuan @p command using a default Assuan transaction and the @p assuanContext
 *  to the GnuPG agent and waits for the result. Returns the status that was sent by
 *  GnuPG agent in response to the @p command.
 *  If an error occurred, then @p err provides details. */
KLEO_EXPORT std::string sendStatusCommand(const std::shared_ptr<GpgME::Context> &assuanContext, const std::string &command, GpgME::Error &err);

}
}
