/*
    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2021 Sandro Knauß <sknauss@kde.org>
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    Based on kpgp.h
    Copyright (C) 2001,2002 the KPGP authors
    See file libkdenetwork/AUTHORS.kpgp for details

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include "expirychecker.h"

#include "dn.h"

#include <libkleo_debug.h>

#include <KLocalizedString>

#include <QGpgME/KeyListJob>
#include <QGpgME/Protocol>

#include <gpgme++/keylistresult.h>

#include <set>

#include <ctime>

using namespace Kleo;

class Kleo::ExpiryCheckerPrivate
{
    Kleo::ExpiryChecker *q;

public:
    ExpiryCheckerPrivate(ExpiryChecker *qq)
        : q{qq}
    {
    }

    Q_REQUIRED_RESULT double calculateSecsTillExpiry(const GpgME::Subkey &key) const;

    void checkKeyNearExpiry(const GpgME::Key &key,
                            bool isOwnKey,
                            bool isSigningKey,
                            bool ca = false,
                            int recur_limit = 100,
                            const GpgME::Key &orig_key = GpgME::Key::null);

    int encryptOwnKeyNearExpiryWarningThreshold;
    int encryptKeyNearExpiryWarningThreshold;
    int encryptRootCertNearExpiryWarningThreshold;
    int encryptChainCertNearExpiryWarningThreshold;

    std::set<QByteArray> alreadyWarnedFingerprints;

    std::shared_ptr<TimeProvider> timeProvider;
};

ExpiryChecker::ExpiryChecker(int encrOwnKeyNearExpiryThresholdDays,
                             int encrKeyNearExpiryThresholdDays,
                             int encrRootCertNearExpiryThresholdDays,
                             int encrChainCertNearExpiryThresholdDays)
    : d{new ExpiryCheckerPrivate{this}}
{
    d->encryptOwnKeyNearExpiryWarningThreshold = encrOwnKeyNearExpiryThresholdDays;
    d->encryptKeyNearExpiryWarningThreshold = encrKeyNearExpiryThresholdDays;
    d->encryptRootCertNearExpiryWarningThreshold = encrRootCertNearExpiryThresholdDays;
    d->encryptChainCertNearExpiryWarningThreshold = encrChainCertNearExpiryThresholdDays;
}

ExpiryChecker::~ExpiryChecker() = default;

int ExpiryChecker::encryptOwnKeyNearExpiryWarningThresholdInDays() const
{
    return d->encryptOwnKeyNearExpiryWarningThreshold;
}

int ExpiryChecker::encryptKeyNearExpiryWarningThresholdInDays() const
{
    return d->encryptKeyNearExpiryWarningThreshold;
}

int ExpiryChecker::encryptRootCertNearExpiryWarningThresholdInDays() const
{
    return d->encryptRootCertNearExpiryWarningThreshold;
}

int ExpiryChecker::encryptChainCertNearExpiryWarningThresholdInDays() const
{
    return d->encryptChainCertNearExpiryWarningThreshold;
}

QString formatOpenPGPMessage(const GpgME::Key &key, int secsTillExpiry, bool isOwnKey, bool isSigningKey)
{
    KLocalizedString msg;
    static const double secsPerDay = 24 * 60 * 60;
    const int daysTillExpiry = 1 + int(abs(secsTillExpiry) / secsPerDay);
    if (secsTillExpiry <= 0) {
        qCDebug(LIBKLEO_LOG) << "Key 0x" << key.keyID() << " expired " << daysTillExpiry << " days ago";
        if (isSigningKey) {
            msg = ki18np(
                "<p>Your OpenPGP signing key</p><p align=center><b>%2</b> (KeyID 0x%3)</p>"
                "<p>expired less than a day ago.</p>",
                "<p>Your OpenPGP signing key</p><p align=center><b>%2</b> (KeyID 0x%3)</p>"
                "<p>expired %1 days ago.</p>");
        } else if (isOwnKey) {
            msg = ki18np(
                "<p>Your OpenPGP encryption key</p><p align=center><b>%2</b> (KeyID 0x%3)</p>"
                "<p>expired less than a day ago.</p>",
                "<p>Your OpenPGP encryption key</p><p align=center><b>%2</b> (KeyID 0x%3)</p>"
                "<p>expired %1 days ago.</p>");
        } else {
            msg = ki18np(
                "<p>The OpenPGP key for</p><p align=center><b>%2</b> (KeyID 0x%3)</p>"
                "<p>expired less than a day ago.</p>",
                "<p>The OpenPGP key for</p><p align=center><b>%2</b> (KeyID 0x%3)</p>"
                "<p>expired %1 days ago.</p>");
        }
    } else {
        qCDebug(LIBKLEO_LOG) << "Key 0x" << key.keyID() << " expires in less than " << daysTillExpiry << " days";
        if (isSigningKey) {
            msg = ki18np(
                "<p>Your OpenPGP signing key</p><p align=center><b>%2</b> (KeyID 0x%3)</p>"
                "<p>expires in less than a day.</p>",
                "<p>Your OpenPGP signing key</p><p align=center><b>%2</b> (KeyID 0x%3)</p>"
                "<p>expires in less than %1 days.</p>");
        } else if (isOwnKey) {
            msg = ki18np(
                "<p>Your OpenPGP encryption key</p><p align=center><b>%2</b> (KeyID 0x%3)</p>"
                "<p>expires in less than a day.</p>",
                "<p>Your OpenPGP encryption key</p><p align=center><b>%2</b> (KeyID 0x%3)</p>"
                "<p>expires in less than %1 days.</p>");
        } else {
            msg = ki18np(
                "<p>The OpenPGP key for</p><p align=center><b>%2</b> (KeyID 0x%3)</p>"
                "<p>expires in less than a day.</p>",
                "<p>The OpenPGP key for</p><p align=center><b>%2</b> (KeyID 0x%3)</p>"
                "<p>expires in less than %1 days.</p>");
        }
    }
    return msg.subs(daysTillExpiry).subs(QString::fromUtf8(key.userID(0).id())).subs(QString::fromLatin1(key.keyID())).toString();
}

QString formatSMIMEMessage(const GpgME::Key &key, const GpgME::Key &orig_key, int secsTillExpiry, bool isOwnKey, bool isSigningKey, bool ca)
{
    KLocalizedString msg;
    static const double secsPerDay = 24 * 60 * 60;
    const int daysTillExpiry = 1 + int(abs(secsTillExpiry) / secsPerDay);
    if (secsTillExpiry <= 0) {
        qCDebug(LIBKLEO_LOG) << "Key 0x" << key.keyID() << " expired " << daysTillExpiry << " days ago";
        if (ca) {
            if (key.isRoot()) {
                if (isSigningKey) {
                    msg = ki18np(
                        "<p>The root certificate</p><p align=center><b>%4</b></p>"
                        "<p>for your S/MIME signing certificate</p><p align=center><b>%2</b> (serial number %3)</p>"
                        "<p>expired less than a day ago.</p>",
                        "<p>The root certificate</p><p align=center><b>%4</b></p>"
                        "<p>for your S/MIME signing certificate</p><p align=center><b>%2</b> (serial number %3)</p>"
                        "<p>expired %1 days ago.</p>");
                } else if (isOwnKey) {
                    msg = ki18np(
                        "<p>The root certificate</p><p align=center><b>%4</b></p>"
                        "<p>for your S/MIME encryption certificate</p><p align=center><b>%2</b> (serial number %3)</p>"
                        "<p>expired less than a day ago.</p>",
                        "<p>The root certificate</p><p align=center><b>%4</b></p>"
                        "<p>for your S/MIME encryption certificate</p><p align=center><b>%2</b> (serial number %3)</p>"
                        "<p>expired %1 days ago.</p>");
                } else {
                    msg = ki18np(
                        "<p>The root certificate</p><p align=center><b>%4</b></p>"
                        "<p>for S/MIME certificate</p><p align=center><b>%2</b> (serial number %3)</p>"
                        "<p>expired less than a day ago.</p>",
                        "<p>The root certificate</p><p align=center><b>%4</b></p>"
                        "<p>for S/MIME certificate</p><p align=center><b>%2</b> (serial number %3)</p>"
                        "<p>expired %1 days ago.</p>");
                }
            } else {
                if (isSigningKey) {
                    msg = ki18np(
                        "<p>The intermediate CA certificate</p><p align=center><b>%4</b></p>"
                        "<p>for your S/MIME signing certificate</p><p align=center><b>%2</b> (serial number %3)</p>"
                        "<p>expired less than a day ago.</p>",
                        "<p>The intermediate CA certificate</p><p align=center><b>%4</b></p>"
                        "<p>for your S/MIME signing certificate</p><p align=center><b>%2</b> (serial number %3)</p>"
                        "<p>expired %1 days ago.</p>");
                } else if (isOwnKey) {
                    msg = ki18np(
                        "<p>The intermediate CA certificate</p><p align=center><b>%4</b></p>"
                        "<p>for your S/MIME encryption certificate</p><p align=center><b>%2</b> (serial number %3)</p>"
                        "<p>expired less than a day ago.</p>",
                        "<p>The intermediate CA certificate</p><p align=center><b>%4</b></p>"
                        "<p>for your S/MIME encryption certificate</p><p align=center><b>%2</b> (serial number %3)</p>"
                        "<p>expired %1 days ago.</p>");
                } else {
                    msg = ki18np(
                        "<p>The intermediate CA certificate</p><p align=center><b>%4</b></p>"
                        "<p>for S/MIME certificate</p><p align=center><b>%2</b> (serial number %3)</p>"
                        "<p>expired less than a day ago.</p>",
                        "<p>The intermediate CA certificate</p><p align=center><b>%4</b></p>"
                        "<p>for S/MIME certificate</p><p align=center><b>%2</b> (serial number %3)</p>"
                        "<p>expired %1 days ago.</p>");
                }
            }
            return msg.subs(daysTillExpiry)
                .subs(Kleo::DN(orig_key.userID(0).id()).prettyDN())
                .subs(QString::fromLatin1(orig_key.issuerSerial()))
                .subs(Kleo::DN(key.userID(0).id()).prettyDN())
                .toString();
        } else {
            if (isSigningKey) {
                msg = ki18np(
                    "<p>Your S/MIME signing certificate</p><p align=center><b>%2</b> (serial number %3)</p>"
                    "<p>expired less than a day ago.</p>",
                    "<p>Your S/MIME signing certificate</p><p align=center><b>%2</b> (serial number %3)</p>"
                    "<p>expired %1 days ago.</p>");
            } else if (isOwnKey) {
                msg = ki18np(
                    "<p>Your S/MIME encryption certificate</p><p align=center><b>%2</b> (serial number %3)</p>"
                    "<p>expired less than a day ago.</p>",
                    "<p>Your S/MIME encryption certificate</p><p align=center><b>%2</b> (serial number %3)</p>"
                    "<p>expired %1 days ago.</p>");
            } else {
                msg = ki18np(
                    "<p>The S/MIME certificate for</p><p align=center><b>%2</b> (serial number %3)</p>"
                    "<p>expired less than a day ago.</p>",
                    "<p>The S/MIME certificate for</p><p align=center><b>%2</b> (serial number %3)</p>"
                    "<p>expired %1 days ago.</p>");
            }
            return msg.subs(daysTillExpiry).subs(Kleo::DN(key.userID(0).id()).prettyDN()).subs(QString::fromLatin1(key.issuerSerial())).toString();
        }
    } else {
        qCDebug(LIBKLEO_LOG) << "Key 0x" << key.keyID() << " expires in less than " << daysTillExpiry << " days";
        if (ca) {
            if (key.isRoot()) {
                if (isSigningKey) {
                    msg = ki18np(
                        "<p>The root certificate</p><p align=center><b>%4</b></p>"
                        "<p>for your S/MIME signing certificate</p><p align=center><b>%2</b> (serial number %3);</p>"
                        "<p>expires in less than a day.</p>",
                        "<p>The root certificate</p><p align=center><b>%4</b></p>"
                        "<p>for your S/MIME signing certificate</p><p align=center><b>%2</b> (serial number %3);</p>"
                        "<p>expires in less than %1 days.</p>");
                } else if (isOwnKey) {
                    msg = ki18np(
                        "<p>The root certificate</p><p align=center><b>%4</b></p>"
                        "<p>for your S/MIME encryption certificate</p><p align=center><b>%2</b> (serial number %3);</p>"
                        "<p>expires in less than a day.</p>",
                        "<p>The root certificate</p><p align=center><b>%4</b></p>"
                        "<p>for your S/MIME encryption certificate</p><p align=center><b>%2</b> (serial number %3);</p>"
                        "<p>expires in less than %1 days.</p>");
                } else {
                    msg = ki18np(
                        "<p>The root certificate</p><p align=center><b>%4</b></p>"
                        "<p>for S/MIME certificate</p><p align=center><b>%2</b> (serial number %3);</p>"
                        "<p>expires in less than a day.</p>",
                        "<p>The root certificate</p><p align=center><b>%4</b></p>"
                        "<p>for S/MIME certificate</p><p align=center><b>%2</b> (serial number %3);</p>"
                        "<p>expires in less than %1 days.</p>");
                }
            } else {
                if (isSigningKey) {
                    msg = ki18np(
                        "<p>The intermediate CA certificate</p><p align=center><b>%4</b></p>"
                        "<p>for your S/MIME signing certificate</p><p align=center><b>%2</b> (serial number %3);</p>"
                        "<p>expires in less than a day.</p>",
                        "<p>The intermediate CA certificate</p><p align=center><b>%4</b></p>"
                        "<p>for your S/MIME signing certificate</p><p align=center><b>%2</b> (serial number %3);</p>"
                        "<p>expires in less than %1 days.</p>");
                } else if (isOwnKey) {
                    msg = ki18np(
                        "<p>The intermediate CA certificate</p><p align=center><b>%4</b></p>"
                        "<p>for your S/MIME encryption certificate</p><p align=center><b>%2</b> (serial number %3);</p>"
                        "<p>expires in less than a day.</p>",
                        "<p>The intermediate CA certificate</p><p align=center><b>%4</b></p>"
                        "<p>for your S/MIME encryption certificate</p><p align=center><b>%2</b> (serial number %3);</p>"
                        "<p>expires in less than %1 days.</p>");
                } else {
                    msg = ki18np(
                        "<p>The intermediate CA certificate</p><p align=center><b>%4</b></p>"
                        "<p>for S/MIME certificate</p><p align=center><b>%2</b> (serial number %3);</p>"
                        "<p>expires in less than a day.</p>",
                        "<p>The intermediate CA certificate</p><p align=center><b>%4</b></p>"
                        "<p>for S/MIME certificate</p><p align=center><b>%2</b> (serial number %3);</p>"
                        "<p>expires in less than %1 days.</p>");
                }
            }
            return msg.subs(daysTillExpiry)
                .subs(Kleo::DN(orig_key.userID(0).id()).prettyDN())
                .subs(QString::fromLatin1(orig_key.issuerSerial()))
                .subs(Kleo::DN(key.userID(0).id()).prettyDN())
                .toString();
        } else {
            if (isSigningKey) {
                msg = ki18np(
                    "<p>Your S/MIME signing certificate</p><p align=center><b>%2</b> (serial number %3);</p>"
                    "<p>expires in less than a day.</p>",
                    "<p>Your S/MIME signing certificate</p><p align=center><b>%2</b> (serial number %3);</p>"
                    "<p>expires in less than %1 days.</p>");
            } else if (isOwnKey) {
                msg = ki18np(
                    "<p>Your S/MIME encryption certificate</p><p align=center><b>%2</b> (serial number %3);</p>"
                    "<p>expires in less than a day.</p>",
                    "<p>Your S/MIME encryption certificate</p><p align=center><b>%2</b> (serial number %3);</p>"
                    "<p>expires in less than %1 days.</p>");
            } else {
                msg = ki18np(
                    "<p>The S/MIME certificate for</p><p align=center><b>%2</b> (serial number %3);</p>"
                    "<p>expires in less than a day.</p>",
                    "<p>The S/MIME certificate for</p><p align=center><b>%2</b> (serial number %3);</p>"
                    "<p>expires in less than %1 days.</p>");
            }
            return msg.subs(daysTillExpiry).subs(Kleo::DN(key.userID(0).id()).prettyDN()).subs(QString::fromLatin1(key.issuerSerial())).toString();
        }
    }
}

double ExpiryCheckerPrivate::calculateSecsTillExpiry(const GpgME::Subkey &key) const
{
    const auto t = timeProvider ? timeProvider->getTime() : std::time(nullptr);
    return std::difftime(key.expirationTime(), t);
}

void ExpiryCheckerPrivate::checkKeyNearExpiry(const GpgME::Key &key, bool isOwnKey, bool isSigningKey, bool ca, int recur_limit, const GpgME::Key &orig_key)
{
    if (recur_limit <= 0) {
        qCDebug(LIBKLEO_LOG) << "Key chain too long (>100 certs)";
        return;
    }
    const GpgME::Subkey subkey = key.subkey(0);

    const bool newMessage = !alreadyWarnedFingerprints.count(subkey.fingerprint());

    if (subkey.neverExpires()) {
        return;
    }
    static const double secsPerDay = 24 * 60 * 60;
    const double secsTillExpiry = calculateSecsTillExpiry(subkey);
    if (secsTillExpiry <= 0) {
        const QString msg = key.protocol() == GpgME::OpenPGP ? formatOpenPGPMessage(key, secsTillExpiry, isOwnKey, isSigningKey)
                                                             : formatSMIMEMessage(key, orig_key, secsTillExpiry, isOwnKey, isSigningKey, ca);
        alreadyWarnedFingerprints.insert(subkey.fingerprint());
        Q_EMIT q->expiryMessage(key, msg, isOwnKey ? ExpiryChecker::OwnKeyExpired : ExpiryChecker::OtherKeyExpired, newMessage);
    } else {
        const int daysTillExpiry = 1 + int(secsTillExpiry / secsPerDay);
        const int threshold = ca ? (key.isRoot() ? encryptRootCertNearExpiryWarningThreshold : encryptChainCertNearExpiryWarningThreshold)
                                 : (isOwnKey ? encryptOwnKeyNearExpiryWarningThreshold : encryptKeyNearExpiryWarningThreshold);
        if (threshold > -1 && daysTillExpiry <= threshold) {
            const QString msg = key.protocol() == GpgME::OpenPGP ? formatOpenPGPMessage(key, secsTillExpiry, isOwnKey, isSigningKey)
                                                                 : formatSMIMEMessage(key, orig_key, secsTillExpiry, isOwnKey, isSigningKey, ca);
            alreadyWarnedFingerprints.insert(subkey.fingerprint());
            Q_EMIT q->expiryMessage(key, msg, isOwnKey ? ExpiryChecker::OwnKeyNearExpiry : ExpiryChecker::OtherKeyNearExpiry, newMessage);
        }
    }
    if (key.isRoot()) {
        return;
    } else if (key.protocol() != GpgME::CMS) { // Key chaining is only possible in SMIME
        return;
    } else if (const char *chain_id = key.chainID()) {
        QGpgME::Protocol *p = QGpgME::smime();
        Q_ASSERT(p);
        std::unique_ptr<QGpgME::KeyListJob> job(p->keyListJob(false, false, true));
        if (job.get()) {
            std::vector<GpgME::Key> keys;
            job->exec(QStringList(QLatin1String(chain_id)), false, keys);
            if (!keys.empty()) {
                return checkKeyNearExpiry(keys.front(), isOwnKey, isSigningKey, true, recur_limit - 1, ca ? orig_key : key);
            }
        }
    }
}

void ExpiryChecker::checkOwnSigningKey(const GpgME::Key &key) const
{
    d->checkKeyNearExpiry(key, /*isOwnKey*/ true, /*isSigningKey*/ true);
}

void ExpiryChecker::checkOwnKey(const GpgME::Key &key) const
{
    d->checkKeyNearExpiry(key, /*isOwnKey*/ true, /*isSigningKey*/ false);
}

void ExpiryChecker::checkKey(const GpgME::Key &key) const
{
    d->checkKeyNearExpiry(key, false, false);
}

void ExpiryChecker::setTimeProviderForTest(const std::shared_ptr<TimeProvider> &timeProvider)
{
    d->timeProvider = timeProvider;
}
