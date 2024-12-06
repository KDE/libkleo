/* -*- mode: c++; c-basic-offset:4 -*-
    utils/keyparameters.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"
#include <gpgme++/key.h>

#include <memory>

class QDate;
class QString;

namespace Kleo
{
class KeyUsage;

class KLEO_EXPORT KeyParameters
{
public:
    enum Protocol {
        NoProtocol,
        OpenPGP,
        CMS,
    };

    KeyParameters();
    explicit KeyParameters(Protocol protocol);
    ~KeyParameters();

    KeyParameters(const KeyParameters &other);
    KeyParameters &operator=(const KeyParameters &other);

    KeyParameters(KeyParameters &&other);
    KeyParameters &operator=(KeyParameters &&other);

    Protocol protocol() const;

    void setKeyType(GpgME::Subkey::PubkeyAlgo type);
    GpgME::Subkey::PubkeyAlgo keyType() const;
    void setCardKeyRef(const QString &cardKeyRef);
    QString cardKeyRef() const;
    void setKeyLength(unsigned int length);
    unsigned int keyLength() const;
    void setKeyCurve(const QString &curve);
    QString keyCurve() const;
    void setKeyUsage(const KeyUsage &usage);
    KeyUsage keyUsage() const;

    void setSubkeyType(GpgME::Subkey::PubkeyAlgo type);
    GpgME::Subkey::PubkeyAlgo subkeyType() const;
    void setSubkeyLength(unsigned int length);
    unsigned int subkeyLength() const;
    void setSubkeyCurve(const QString &curve);
    QString subkeyCurve() const;
    void setSubkeyUsage(const KeyUsage &usage);
    KeyUsage subkeyUsage() const;

    void setExpirationDate(const QDate &date);
    QDate expirationDate() const;

    void setName(const QString &name);
    QString name() const;
    void setComment(const QString &comment);
    QString comment() const;
    void setDN(const QString &dn);
    QString dn() const;
    void setEmail(const QString &email);
    void addEmail(const QString &email);
    std::vector<QString> emails() const;
    void addDomainName(const QString &domain);
    std::vector<QString> domainNames() const;
    void addURI(const QString &uri);
    std::vector<QString> uris() const;

    QString serial() const;
    void setSerial(const QString &serial);
    void setUseRandomSerial();

    QString toString() const;

private:
    class Private;
    std::unique_ptr<Private> d;
};

}
