/*  -*- c++ -*-
    kleo/keyresolvercore.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2018 Intevation GmbH
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <Libkleo/KeyResolver>

#include <QMap>
#include <QStringList>

#include <gpgme++/global.h>

#include <memory>
#include <vector>

class QString;

namespace GpgME
{
class Key;
}

namespace Kleo
{

class KLEO_EXPORT KeyResolverCore
{
public:
    enum SolutionFlags {
        // clang-format off
        SomeUnresolved = 0,
        AllResolved    = 1,

        OpenPGPOnly    = 2,
        CMSOnly        = 4,
        MixedProtocols = OpenPGPOnly | CMSOnly,

        Error          = 0x1000,

        ResolvedMask   = AllResolved | Error,
        ProtocolsMask  = OpenPGPOnly | CMSOnly | Error,
        // clang-format on
    };
    struct Result {
        SolutionFlags flags;
        KeyResolver::Solution solution;
        KeyResolver::Solution alternative;
    };

    explicit KeyResolverCore(bool encrypt, bool sign, GpgME::Protocol format = GpgME::UnknownProtocol);
    ~KeyResolverCore();

    void setSender(const QString &sender);
    QString normalizedSender() const;

    void setRecipients(const QStringList &addresses);

    void setSigningKeys(const QStringList &fingerprints);

    void setOverrideKeys(const QMap<GpgME::Protocol, QMap<QString, QStringList>> &overrides);

    void setAllowMixedProtocols(bool allowMixed);

    void setPreferredProtocol(GpgME::Protocol proto);

    void setMinimumValidity(int validity);

    Result resolve();

private:
    class Private;
    std::unique_ptr<Private> d;
};

} // namespace Kleo
