/* -*- mode: c++; c-basic-offset:4 -*-
    utils/keyparameters.cpp

    This file is part of Libkleo
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2020, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "keyparameters.h"

#include <Libkleo/KeyUsage>

#include <QDate>
#include <QUrl>

#include "libkleo_debug.h"

using namespace Kleo;
using namespace GpgME;
using namespace Qt::StringLiterals;

namespace
{
QString encodeDomainName(const QString &domain)
{
    const QByteArray encodedDomain = QUrl::toAce(domain);
    return encodedDomain.isEmpty() ? domain : QString::fromLatin1(encodedDomain);
}

QString encodeEmail(const QString &email)
{
    const int at = email.lastIndexOf(QLatin1Char('@'));
    if (at < 0) {
        return email;
    }
    return email.left(at + 1) + encodeDomainName(email.mid(at + 1));
}
}

class KeyParameters::Private
{
    friend class ::Kleo::KeyParameters;

    Protocol protocol;

    Subkey::PubkeyAlgo keyType = Subkey::AlgoUnknown;
    QString cardKeyRef;
    unsigned int keyLength = 0;
    QString keyCurve;
    KeyUsage keyUsage;

    Subkey::PubkeyAlgo subkeyType = Subkey::AlgoUnknown;
    unsigned int subkeyLength = 0;
    QString subkeyCurve;
    KeyUsage subkeyUsage;

    QString name;
    QString comment;
    QString dn;
    std::vector<QString> emailAdresses;
    std::vector<QString> domainNames;
    std::vector<QString> uris;
    QString serial;

    QDate expirationDate;

    QString issuerDN;

public:
    explicit Private(Protocol proto)
        : protocol(proto)
    {
    }
};

KeyParameters::KeyParameters()
    : KeyParameters{NoProtocol}
{
}

KeyParameters::KeyParameters(Protocol protocol)
    : d{new Private{protocol}}
{
}

KeyParameters::~KeyParameters() = default;

KeyParameters::KeyParameters(const KeyParameters &other)
    : d{new Private{*other.d}}
{
}

KeyParameters &KeyParameters::operator=(const KeyParameters &other)
{
    *d = *other.d;
    return *this;
}

KeyParameters::KeyParameters(KeyParameters &&other) = default;

KeyParameters &KeyParameters::operator=(KeyParameters &&other) = default;

KeyParameters::Protocol KeyParameters::protocol() const
{
    return d->protocol;
}

void KeyParameters::setKeyType(Subkey::PubkeyAlgo type)
{
    d->keyType = type;
}

GpgME::Subkey::PubkeyAlgo KeyParameters::keyType() const
{
    return d->keyType;
}

void KeyParameters::setCardKeyRef(const QString &cardKeyRef)
{
    d->cardKeyRef = cardKeyRef;
}

QString KeyParameters::cardKeyRef() const
{
    return d->cardKeyRef;
}

void KeyParameters::setKeyLength(unsigned int length)
{
    d->keyLength = length;
}

unsigned int KeyParameters::keyLength() const
{
    return d->keyLength;
}

void KeyParameters::setKeyCurve(const QString &curve)
{
    d->keyCurve = curve;
}

QString KeyParameters::keyCurve() const
{
    return d->keyCurve;
}

void KeyParameters::setKeyUsage(const KeyUsage &usage)
{
    d->keyUsage = usage;
}

KeyUsage KeyParameters::keyUsage() const
{
    return d->keyUsage;
}

void KeyParameters::setSubkeyType(Subkey::PubkeyAlgo type)
{
    d->subkeyType = type;
}

Subkey::PubkeyAlgo KeyParameters::subkeyType() const
{
    return d->subkeyType;
}

void KeyParameters::setSubkeyLength(unsigned int length)
{
    d->subkeyLength = length;
}

unsigned int KeyParameters::subkeyLength() const
{
    return d->subkeyLength;
}

void KeyParameters::setSubkeyCurve(const QString &curve)
{
    d->subkeyCurve = curve;
}

QString KeyParameters::subkeyCurve() const
{
    return d->subkeyCurve;
}

void KeyParameters::setSubkeyUsage(const KeyUsage &usage)
{
    d->subkeyUsage = usage;
}

KeyUsage KeyParameters::subkeyUsage() const
{
    return d->subkeyUsage;
}

void KeyParameters::setExpirationDate(const QDate &date)
{
    d->expirationDate = date;
}

QDate KeyParameters::expirationDate() const
{
    return d->expirationDate;
}

void KeyParameters::setName(const QString &name)
{
    d->name = name;
}

QString KeyParameters::name() const
{
    return d->name;
}

void KeyParameters::setComment(const QString &comment)
{
    d->comment = comment;
}

QString KeyParameters::comment() const
{
    return d->comment;
}

void KeyParameters::setDN(const QString &dn)
{
    d->dn = dn;
}

QString KeyParameters::dn() const
{
    return d->dn;
}

void KeyParameters::setEmail(const QString &email)
{
    d->emailAdresses = {email};
}

void KeyParameters::addEmail(const QString &email)
{
    d->emailAdresses.push_back(email);
}

std::vector<QString> KeyParameters::emails() const
{
    return d->emailAdresses;
}

void KeyParameters::addDomainName(const QString &domain)
{
    d->domainNames.push_back(domain);
}

std::vector<QString> KeyParameters::domainNames() const
{
    return d->domainNames;
}

void KeyParameters::addURI(const QString &uri)
{
    d->uris.push_back(uri);
}

std::vector<QString> KeyParameters::uris() const
{
    return d->uris;
}

QString KeyParameters::serial() const
{
    return d->serial;
}

void KeyParameters::setSerial(const QString &serial)
{
    d->serial = serial;
}

void KeyParameters::setUseRandomSerial()
{
    d->serial = u"random"_s;
}

QString KeyParameters::issuerDN() const
{
    return d->issuerDN;
}

void KeyParameters::setIssuerDN(const QString &issuerDN)
{
    d->issuerDN = issuerDN;
}

namespace
{
QString serialize(Subkey::PubkeyAlgo algo)
{
    return QString::fromLatin1(Subkey::publicKeyAlgorithmAsString(algo));
}

QString serialize(unsigned int number)
{
    return QString::number(number);
}

QString serialize(KeyUsage keyUsage)
{
    QStringList usages;
    if (keyUsage.canSign()) {
        usages << QStringLiteral("sign");
    }
    if (keyUsage.canEncrypt()) {
        usages << QStringLiteral("encrypt");
    }
    if (keyUsage.canAuthenticate()) {
        usages << QStringLiteral("auth");
    }
    if (keyUsage.canCertify()) {
        usages << QStringLiteral("cert");
    }
    return usages.join(QLatin1Char{' '});
}

QString serialize(const QDate &date)
{
    return date.toString(Qt::ISODate);
}

QString serialize(const char *key, const QString &value)
{
    return QString::fromLatin1(key) + QLatin1Char(':') + value;
}
}

QString KeyParameters::toString() const
{
    QStringList keyParameters;

    keyParameters.push_back(QLatin1StringView("<GnupgKeyParms format=\"internal\">"));

    if (d->protocol == OpenPGP) {
        // for backward compatibility with GnuPG 2.0 and earlier
        keyParameters.push_back(QStringLiteral("%ask-passphrase"));
    }

    // add Key-Type as first parameter
    if (!d->cardKeyRef.isEmpty()) {
        keyParameters.push_back(serialize("Key-Type", QLatin1StringView{"card:"} + d->cardKeyRef));
    } else if (d->keyType != Subkey::AlgoUnknown) {
        keyParameters.push_back(serialize("Key-Type", serialize(d->keyType)));
    } else {
        qCWarning(LIBKLEO_LOG) << "KeyParameters::toString(): Key type is unset/empty";
    }
    if (d->keyLength) {
        keyParameters.push_back(serialize("Key-Length", serialize(d->keyLength)));
    }
    if (!d->keyCurve.isEmpty()) {
        keyParameters.push_back(serialize("Key-Curve", d->keyCurve));
    }
    keyParameters.push_back(serialize("Key-Usage", serialize(d->keyUsage)));

    if (d->subkeyType != Subkey::AlgoUnknown) {
        keyParameters.push_back(serialize("Subkey-Type", serialize(d->subkeyType)));
        if (d->subkeyUsage.value()) {
            keyParameters.push_back(serialize("Subkey-Usage", serialize(d->subkeyUsage)));
        }
        if (d->subkeyLength) {
            keyParameters.push_back(serialize("Subkey-Length", serialize(d->subkeyLength)));
        }
        if (!d->subkeyCurve.isEmpty()) {
            keyParameters.push_back(serialize("Subkey-Curve", d->subkeyCurve));
        }
    }

    if (d->expirationDate.isValid()) {
        keyParameters.push_back(serialize("Expire-Date", serialize(d->expirationDate)));
    }

    if (!d->serial.isEmpty()) {
        keyParameters.push_back(serialize("Serial", d->serial));
    }

    if (!d->issuerDN.isEmpty()) {
        keyParameters.push_back(serialize("Issuer-DN", d->issuerDN));
    }

    if (!d->name.isEmpty()) {
        keyParameters.push_back(serialize("Name-Real", d->name));
    }
    if (!d->comment.isEmpty()) {
        keyParameters.push_back(serialize("Name-Comment", d->comment));
    }
    if (!d->dn.isEmpty()) {
        keyParameters.push_back(serialize("Name-DN", d->dn));
    }
    std::transform(std::cbegin(d->emailAdresses), std::cend(d->emailAdresses), std::back_inserter(keyParameters), [this](const auto &email) {
        return serialize("Name-Email", (d->protocol == CMS) ? encodeEmail(email) : email);
    });
    std::transform(std::cbegin(d->domainNames), std::cend(d->domainNames), std::back_inserter(keyParameters), [](const auto &domain) {
        return serialize("Name-DNS", encodeDomainName(domain));
    });
    std::transform(std::cbegin(d->uris), std::cend(d->uris), std::back_inserter(keyParameters), [](const auto &uri) {
        return serialize("Name-URI", uri);
    });

    keyParameters.push_back(QLatin1StringView("</GnupgKeyParms>"));

    return keyParameters.join(QLatin1Char('\n'));
}
