/*
    utils/assuan.cpp

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2021, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "assuan.h"

#include <libkleo_debug.h>

#include <QThread>

#if __has_include(<QGpgME/Debug>)
#include <QGpgME/Debug>
#endif

#include <gpgme++/context.h>
#include <gpgme++/defaultassuantransaction.h>
#include <gpgme++/error.h>

using namespace GpgME;
using namespace Kleo;
using namespace Kleo::Assuan;
using namespace std::chrono_literals;

static const auto initialRetryDelay = 125ms;
static const auto maxRetryDelay = 1000ms;
static const auto maxConnectionAttempts = 10;

namespace
{
static QDebug operator<<(QDebug s, const std::string &string)
{
    return s << QString::fromStdString(string);
}

static QDebug operator<<(QDebug s, const std::vector<std::pair<std::string, std::string>> &v)
{
    using pair = std::pair<std::string, std::string>;
    s << '(';
    for (const pair &p : v) {
        s << "status(" << QString::fromStdString(p.first) << ") =" << QString::fromStdString(p.second) << '\n';
    }
    return s << ')';
}
}

bool Kleo::Assuan::agentIsRunning()
{
    Error err;
    const std::unique_ptr<Context> ctx = Context::createForEngine(AssuanEngine, &err);
    if (err) {
        qCWarning(LIBKLEO_LOG) << __func__ << ": Creating context for Assuan engine failed:" << err;
        return false;
    }
    static const char *command = "GETINFO version";
    err = ctx->assuanTransact(command);
    if (!err) {
        // all good
    } else if (err.code() == GPG_ERR_ASS_CONNECT_FAILED) {
        qCDebug(LIBKLEO_LOG) << __func__ << ": Connecting to the agent failed.";
    } else {
        qCWarning(LIBKLEO_LOG) << __func__ << ": Starting Assuan transaction for" << command << "failed:" << err;
    }
    return !err;
}

std::unique_ptr<GpgME::AssuanTransaction> Kleo::Assuan::sendCommand(std::shared_ptr<GpgME::Context> &context,
                                                                    const std::string &command,
                                                                    std::unique_ptr<GpgME::AssuanTransaction> transaction,
                                                                    GpgME::Error &err)
{
    qCDebug(LIBKLEO_LOG) << __func__ << command;
    int connectionAttempts = 1;
    err = context->assuanTransact(command.c_str(), std::move(transaction));

    auto retryDelay = initialRetryDelay;
    while (err.code() == GPG_ERR_ASS_CONNECT_FAILED && connectionAttempts < maxConnectionAttempts) {
        // Esp. on Windows the agent processes may take their time so we try
        // in increasing waits for them to start up
        qCDebug(LIBKLEO_LOG) << "Connecting to the agent failed. Retrying in" << retryDelay.count() << "ms";
        QThread::msleep(retryDelay.count());
        retryDelay = std::min(retryDelay * 2, maxRetryDelay);
        connectionAttempts++;
        err = context->assuanTransact(command.c_str(), context->takeLastAssuanTransaction());
    }
    if (err.code()) {
        qCDebug(LIBKLEO_LOG) << __func__ << command << "failed:" << err;
        if (err.code() >= GPG_ERR_ASS_GENERAL && err.code() <= GPG_ERR_ASS_UNKNOWN_INQUIRE) {
            qCDebug(LIBKLEO_LOG) << "Assuan problem, killing context";
            context.reset();
        }
        return {};
    }
    return context->takeLastAssuanTransaction();
}

std::unique_ptr<DefaultAssuanTransaction> Kleo::Assuan::sendCommand(std::shared_ptr<Context> &context, const std::string &command, Error &err)
{
    std::unique_ptr<AssuanTransaction> t = sendCommand(context, command, std::make_unique<DefaultAssuanTransaction>(), err);
    return std::unique_ptr<DefaultAssuanTransaction>(dynamic_cast<DefaultAssuanTransaction *>(t.release()));
}

std::string Kleo::Assuan::sendDataCommand(std::shared_ptr<Context> context, const std::string &command, Error &err)
{
    std::string data;
    const std::unique_ptr<DefaultAssuanTransaction> t = sendCommand(context, command, err);
    if (t.get()) {
        data = t->data();
        qCDebug(LIBKLEO_LOG) << __func__ << command << ": got" << QString::fromStdString(data);
    } else {
        qCDebug(LIBKLEO_LOG) << __func__ << command << ": t == NULL";
    }
    return data;
}

std::vector<std::pair<std::string, std::string>> Kleo::Assuan::sendStatusLinesCommand(std::shared_ptr<Context> context, const std::string &command, Error &err)
{
    std::vector<std::pair<std::string, std::string>> statusLines;
    const std::unique_ptr<DefaultAssuanTransaction> t = sendCommand(context, command, err);
    if (t.get()) {
        statusLines = t->statusLines();
        qCDebug(LIBKLEO_LOG) << __func__ << command << ": got" << statusLines;
    } else {
        qCDebug(LIBKLEO_LOG) << __func__ << command << ": t == NULL";
    }
    return statusLines;
}

std::string Kleo::Assuan::sendStatusCommand(const std::shared_ptr<Context> &context, const std::string &command, Error &err)
{
    const auto lines = sendStatusLinesCommand(context, command, err);
    // The status is only the last attribute
    // e.g. for SCD SERIALNO it would only be "SERIALNO" and for SCD GETATTR FOO
    // it would only be FOO
    const auto lastSpace = command.rfind(' ');
    const auto needle = lastSpace == std::string::npos ? command : command.substr(lastSpace + 1);
    for (const auto &pair : lines) {
        if (pair.first == needle) {
            return pair.second;
        }
    }
    return {};
}
