/*  -*- c++ -*-
    kleo/keyresolvercore.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2018 Intevation GmbH
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifndef __LIBKLEO_KEYRESOLVERCORE_H__
#define __LIBKLEO_KEYRESOLVERCORE_H__

#include "kleo_export.h"

#include <QMap>

#include <gpgme++/global.h>

#include <memory>
#include <vector>

class QString;
class QStringList;

namespace GpgME
{
class Key;
}

namespace Kleo
{

class KLEO_EXPORT KeyResolverCore
{
public:
    explicit KeyResolverCore(bool encrypt, bool sign,
                             GpgME::Protocol format = GpgME::UnknownProtocol);
    ~KeyResolverCore();

    void setSender(const QString &sender);
    QString normalizedSender() const;

    void setRecipients(const QStringList &addresses);

    void setSigningKeys(const QStringList &fingerprints);

    void setOverrideKeys(const QMap<GpgME::Protocol, QMap<QString, QStringList> > &overrides);

    void setAllowMixedProtocols(bool allowMixed);

    void setPreferredProtocol(GpgME::Protocol proto);

    void setMinimumValidity(int validity);

    bool resolve();

    QMap<GpgME::Protocol, std::vector<GpgME::Key> > signingKeys() const;

    QMap<GpgME::Protocol, QMap<QString, std::vector<GpgME::Key> > > encryptionKeys() const;

    QStringList unresolvedRecipients(GpgME::Protocol protocol) const;

private:
    class Private;
    std::unique_ptr<Private> d;
};

} // namespace Kleo

#endif // __LIBKLEO_KEYRESOLVER_H__
