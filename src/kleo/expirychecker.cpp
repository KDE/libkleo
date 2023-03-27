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

#include "debug.h"
#include "dn.h"

#include <libkleo_debug.h>

#include <KLocalizedString>

#include <QGpgME/KeyListJob>
#include <QGpgME/Protocol>

#include <gpgme++/keylistresult.h>

#include <set>

#include <cmath>
#include <ctime>

using namespace Kleo;

namespace
{
struct Expiration {
    enum Status {
        NeverExpires,
        Expires,
        Expired,
    } status;
    // duration is full days until expiry if status is Expires,
    // full days since expiry if status is Expired,
    // undefined if status is NeverExpires
    Kleo::chrono::days duration;
};
}

class Kleo::ExpiryCheckerPrivate
{
    Kleo::ExpiryChecker *q;

public:
    ExpiryCheckerPrivate(ExpiryChecker *qq)
        : q{qq}
    {
    }

    Expiration calculateExpiration(const GpgME::Subkey &key) const;

    void checkKeyNearExpiry(const GpgME::Key &key,
                            bool isOwnKey,
                            bool isSigningKey,
                            bool ca = false,
                            int recur_limit = 100,
                            const GpgME::Key &orig_key = GpgME::Key::null);

    Kleo::chrono::days ownKeyThreshold;
    Kleo::chrono::days otherKeyThreshold;
    Kleo::chrono::days rootCertThreshold;
    Kleo::chrono::days chainCertThreshold;
    std::set<QByteArray> alreadyWarnedFingerprints;
    std::shared_ptr<TimeProvider> timeProvider;
};

ExpiryChecker::ExpiryChecker(Kleo::chrono::days ownKeyThreshold,
                             Kleo::chrono::days otherKeyThreshold,
                             Kleo::chrono::days rootCertThreshold,
                             Kleo::chrono::days chainCertThreshold)
    : d{new ExpiryCheckerPrivate{this}}
{
    d->ownKeyThreshold = ownKeyThreshold;
    d->otherKeyThreshold = otherKeyThreshold;
    d->rootCertThreshold = rootCertThreshold;
    d->chainCertThreshold = chainCertThreshold;
}

ExpiryChecker::~ExpiryChecker() = default;

Kleo::chrono::days ExpiryChecker::ownKeyThreshold() const
{
    return d->ownKeyThreshold;
}

Kleo::chrono::days ExpiryChecker::otherKeyThreshold() const
{
    return d->otherKeyThreshold;
}

Kleo::chrono::days ExpiryChecker::rootCertThreshold() const
{
    return d->rootCertThreshold;
}

Kleo::chrono::days ExpiryChecker::chainCertThreshold() const
{
    return d->chainCertThreshold;
}

QString formatOpenPGPMessage(const GpgME::Key &key, Expiration expiration, bool isOwnKey, bool isSigningKey)
{
    const auto keyInfo = ki18nc("<b>User ID of key</b> (KeyID key ID of key in hex notation)", "<b>%1</b> (KeyID 0x%2)")
                             .subs(QString::fromUtf8(key.userID(0).id()))
                             .subs(QString::fromLatin1(key.keyID()));
    if (expiration.status == Expiration::Expired) {
        qCDebug(LIBKLEO_LOG) << "Key" << key << "expired" << expiration.duration.count() << "days ago";
        if (expiration.duration.count() == 0) {
            KLocalizedString msg;
            if (isSigningKey) {
                msg = ki18n("<p>Your OpenPGP signing key</p><p align=center>%1</p><p>expired less than a day ago.</p>");
            } else if (isOwnKey) {
                msg = ki18n("<p>Your OpenPGP encryption key</p><p align=center>%1</p><p>expired less than a day ago.</p>");
            } else {
                msg = ki18n("<p>The OpenPGP key for</p><p align=center>%1</p><p>expired less than a day ago.</p>");
            }
            return msg.subs(keyInfo).toString();
        }
        KLocalizedString msg;
        if (isSigningKey) {
            msg = ki18np(
                "<p>Your OpenPGP signing key</p><p align=center>%2</p>"
                "<p>expired one day ago.</p>",
                "<p>Your OpenPGP signing key</p><p align=center>%2</p>"
                "<p>expired %1 days ago.</p>");
        } else if (isOwnKey) {
            msg = ki18np(
                "<p>Your OpenPGP encryption key</p><p align=center>%2</p>"
                "<p>expired one day ago.</p>",
                "<p>Your OpenPGP encryption key</p><p align=center>%2</p>"
                "<p>expired %1 days ago.</p>");
        } else {
            msg = ki18np(
                "<p>The OpenPGP key for</p><p align=center>%2</p>"
                "<p>expired one day ago.</p>",
                "<p>The OpenPGP key for</p><p align=center>%2</p>"
                "<p>expired %1 days ago.</p>");
        }
        return msg.subs(expiration.duration.count()).subs(keyInfo).toString();
    }
    qCDebug(LIBKLEO_LOG) << "Key" << key << "expires in less than" << expiration.duration.count() + 1 << "days";
    KLocalizedString msg;
    if (isSigningKey) {
        msg = ki18np(
            "<p>Your OpenPGP signing key</p><p align=center>%2</p>"
            "<p>expires in less than a day.</p>",
            "<p>Your OpenPGP signing key</p><p align=center>%2</p>"
            "<p>expires in less than %1 days.</p>");
    } else if (isOwnKey) {
        msg = ki18np(
            "<p>Your OpenPGP encryption key</p><p align=center>%2</p>"
            "<p>expires in less than a day.</p>",
            "<p>Your OpenPGP encryption key</p><p align=center>%2</p>"
            "<p>expires in less than %1 days.</p>");
    } else {
        msg = ki18np(
            "<p>The OpenPGP key for</p><p align=center>%2</p>"
            "<p>expires in less than a day.</p>",
            "<p>The OpenPGP key for</p><p align=center>%2</p>"
            "<p>expires in less than %1 days.</p>");
    }
    return msg.subs(expiration.duration.count() + 1).subs(keyInfo).toString();
}

QString formatSMIMEMessage(const GpgME::Key &key, const GpgME::Key &orig_key, Expiration expiration, bool isOwnKey, bool isSigningKey, bool ca)
{
    const auto userCert = orig_key.isNull() ? key : orig_key;
    const auto userCertInfo = ki18nc("<b>User ID of certificate</b> (serial number serial no. of certificate)", "<b>%1</b> (serial number %2)")
                                  .subs(Kleo::DN(userCert.userID(0).id()).prettyDN())
                                  .subs(QString::fromLatin1(userCert.issuerSerial()));
    if (expiration.status == Expiration::Expired) {
        qCDebug(LIBKLEO_LOG) << "Certificate" << key << "expired" << expiration.duration.count() << "days ago";
        if (ca) {
            if (key.isRoot()) {
                if (expiration.duration.count() == 0) {
                    KLocalizedString msg;
                    if (isSigningKey) {
                        msg = ki18n(
                            "<p>The root certificate</p><p align=center><b>%2</b></p>"
                            "<p>for your S/MIME signing certificate</p><p align=center>%1</p>"
                            "<p>expired less than a day ago.</p>");
                    } else if (isOwnKey) {
                        msg = ki18n(
                            "<p>The root certificate</p><p align=center><b>%2</b></p>"
                            "<p>for your S/MIME encryption certificate</p><p align=center>%1</p>"
                            "<p>expired less than a day ago.</p>");
                    } else {
                        msg = ki18n(
                            "<p>The root certificate</p><p align=center><b>%2</b></p>"
                            "<p>for S/MIME certificate</p><p align=center>%1</p>"
                            "<p>expired less than a day ago.</p>");
                    }
                    return msg.subs(userCertInfo).subs(Kleo::DN(key.userID(0).id()).prettyDN()).toString();
                }
                KLocalizedString msg;
                if (isSigningKey) {
                    msg = ki18np(
                        "<p>The root certificate</p><p align=center><b>%3</b></p>"
                        "<p>for your S/MIME signing certificate</p><p align=center>%2</p>"
                        "<p>expired one day ago.</p>",
                        "<p>The root certificate</p><p align=center><b>%3</b></p>"
                        "<p>for your S/MIME signing certificate</p><p align=center>%2</p>"
                        "<p>expired %1 days ago.</p>");
                } else if (isOwnKey) {
                    msg = ki18np(
                        "<p>The root certificate</p><p align=center><b>%3</b></p>"
                        "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                        "<p>expired one day ago.</p>",
                        "<p>The root certificate</p><p align=center><b>%3</b></p>"
                        "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                        "<p>expired %1 days ago.</p>");
                } else {
                    msg = ki18np(
                        "<p>The root certificate</p><p align=center><b>%3</b></p>"
                        "<p>for S/MIME certificate</p><p align=center>%2</p>"
                        "<p>expired one day ago.</p>",
                        "<p>The root certificate</p><p align=center><b>%3</b></p>"
                        "<p>for S/MIME certificate</p><p align=center>%2</p>"
                        "<p>expired %1 days ago.</p>");
                }
                return msg.subs(expiration.duration.count()).subs(userCertInfo).subs(Kleo::DN(key.userID(0).id()).prettyDN()).toString();
            } else {
                if (expiration.duration.count() == 0) {
                    KLocalizedString msg;
                    if (isSigningKey) {
                        msg = ki18n(
                            "<p>The intermediate CA certificate</p><p align=center><b>%2</b></p>"
                            "<p>for your S/MIME signing certificate</p><p align=center>%1</p>"
                            "<p>expired less than a day ago.</p>");
                    } else if (isOwnKey) {
                        msg = ki18n(
                            "<p>The intermediate CA certificate</p><p align=center><b>%2</b></p>"
                            "<p>for your S/MIME encryption certificate</p><p align=center>%1</p>"
                            "<p>expired less than a day ago.</p>");
                    } else {
                        msg = ki18n(
                            "<p>The intermediate CA certificate</p><p align=center><b>%2</b></p>"
                            "<p>for S/MIME certificate</p><p align=center>%1</p>"
                            "<p>expired less than a day ago.</p>");
                    }
                    return msg.subs(userCertInfo).subs(Kleo::DN(key.userID(0).id()).prettyDN()).toString();
                }
                KLocalizedString msg;
                if (isSigningKey) {
                    msg = ki18np(
                        "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                        "<p>for your S/MIME signing certificate</p><p align=center>%2</p>"
                        "<p>expired less than a day ago.</p>",
                        "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                        "<p>for your S/MIME signing certificate</p><p align=center>%2</p>"
                        "<p>expired %1 days ago.</p>");
                } else if (isOwnKey) {
                    msg = ki18np(
                        "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                        "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                        "<p>expired less than a day ago.</p>",
                        "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                        "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                        "<p>expired %1 days ago.</p>");
                } else {
                    msg = ki18np(
                        "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                        "<p>for S/MIME certificate</p><p align=center>%2</p>"
                        "<p>expired less than a day ago.</p>",
                        "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                        "<p>for S/MIME certificate</p><p align=center>%2</p>"
                        "<p>expired %1 days ago.</p>");
                }
                return msg.subs(expiration.duration.count()).subs(userCertInfo).subs(Kleo::DN(key.userID(0).id()).prettyDN()).toString();
            }
        } else {
            if (expiration.duration.count() == 0) {
                KLocalizedString msg;
                if (isSigningKey) {
                    msg = ki18n("<p>Your S/MIME signing certificate</p><p align=center>%1</p><p>expired less than a day ago.</p>");
                } else if (isOwnKey) {
                    msg = ki18n("<p>Your S/MIME encryption certificate</p><p align=center>%1</p><p>expired less than a day ago.</p>");
                } else {
                    msg = ki18n("<p>The S/MIME certificate for</p><p align=center>%1</p><p>expired less than a day ago.</p>");
                }
                return msg.subs(userCertInfo).toString();
            }
            KLocalizedString msg;
            if (isSigningKey) {
                msg = ki18np(
                    "<p>Your S/MIME signing certificate</p><p align=center>%2</p>"
                    "<p>expired less than a day ago.</p>",
                    "<p>Your S/MIME signing certificate</p><p align=center>%2</p>"
                    "<p>expired %1 days ago.</p>");
            } else if (isOwnKey) {
                msg = ki18np(
                    "<p>Your S/MIME encryption certificate</p><p align=center>%2</p>"
                    "<p>expired less than a day ago.</p>",
                    "<p>Your S/MIME encryption certificate</p><p align=center>%2</p>"
                    "<p>expired %1 days ago.</p>");
            } else {
                msg = ki18np(
                    "<p>The S/MIME certificate for</p><p align=center>%2</p>"
                    "<p>expired less than a day ago.</p>",
                    "<p>The S/MIME certificate for</p><p align=center>%2</p>"
                    "<p>expired %1 days ago.</p>");
            }
            return msg.subs(expiration.duration.count()).subs(userCertInfo).toString();
        }
    }
    qCDebug(LIBKLEO_LOG) << "Certificate" << key << "expires in less than" << expiration.duration.count() + 1 << "days";
    KLocalizedString msg;
    if (ca) {
        if (key.isRoot()) {
            if (isSigningKey) {
                msg = ki18np(
                    "<p>The root certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME signing certificate</p><p align=center>%2;</p>"
                    "<p>expires in less than a day.</p>",
                    "<p>The root certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME signing certificate</p><p align=center>%2;</p>"
                    "<p>expires in less than %1 days.</p>");
            } else if (isOwnKey) {
                msg = ki18np(
                    "<p>The root certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME encryption certificate</p><p align=center>%2;</p>"
                    "<p>expires in less than a day.</p>",
                    "<p>The root certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME encryption certificate</p><p align=center>%2;</p>"
                    "<p>expires in less than %1 days.</p>");
            } else {
                msg = ki18np(
                    "<p>The root certificate</p><p align=center><b>%3</b></p>"
                    "<p>for S/MIME certificate</p><p align=center>%2;</p>"
                    "<p>expires in less than a day.</p>",
                    "<p>The root certificate</p><p align=center><b>%3</b></p>"
                    "<p>for S/MIME certificate</p><p align=center>%2;</p>"
                    "<p>expires in less than %1 days.</p>");
            }
        } else {
            if (isSigningKey) {
                msg = ki18np(
                    "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME signing certificate</p><p align=center>%2;</p>"
                    "<p>expires in less than a day.</p>",
                    "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME signing certificate</p><p align=center>%2;</p>"
                    "<p>expires in less than %1 days.</p>");
            } else if (isOwnKey) {
                msg = ki18np(
                    "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME encryption certificate</p><p align=center>%2;</p>"
                    "<p>expires in less than a day.</p>",
                    "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME encryption certificate</p><p align=center>%2;</p>"
                    "<p>expires in less than %1 days.</p>");
            } else {
                msg = ki18np(
                    "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                    "<p>for S/MIME certificate</p><p align=center>%2;</p>"
                    "<p>expires in less than a day.</p>",
                    "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                    "<p>for S/MIME certificate</p><p align=center>%2;</p>"
                    "<p>expires in less than %1 days.</p>");
            }
        }
        return msg.subs(expiration.duration.count() + 1).subs(userCertInfo).subs(Kleo::DN(key.userID(0).id()).prettyDN()).toString();
    }
    if (isSigningKey) {
        msg = ki18np(
            "<p>Your S/MIME signing certificate</p><p align=center>%2;</p>"
            "<p>expires in less than a day.</p>",
            "<p>Your S/MIME signing certificate</p><p align=center>%2;</p>"
            "<p>expires in less than %1 days.</p>");
    } else if (isOwnKey) {
        msg = ki18np(
            "<p>Your S/MIME encryption certificate</p><p align=center>%2;</p>"
            "<p>expires in less than a day.</p>",
            "<p>Your S/MIME encryption certificate</p><p align=center>%2;</p>"
            "<p>expires in less than %1 days.</p>");
    } else {
        msg = ki18np(
            "<p>The S/MIME certificate for</p><p align=center>%2;</p>"
            "<p>expires in less than a day.</p>",
            "<p>The S/MIME certificate for</p><p align=center>%2;</p>"
            "<p>expires in less than %1 days.</p>");
    }
    return msg.subs(expiration.duration.count() + 1).subs(userCertInfo).toString();
}

Expiration ExpiryCheckerPrivate::calculateExpiration(const GpgME::Subkey &subkey) const
{
    if (subkey.neverExpires()) {
        return {Expiration::NeverExpires, Kleo::chrono::days::zero()};
    }
    const time_t t = timeProvider ? timeProvider->getTime() : std::time(nullptr);
    // casting the double-valued difference (returned by std::difftime) of two non-negative time_t to a time_t is no problem;
    // negative values for expiration time and current time can be safely ignored
    const time_t secsTillExpiry = static_cast<time_t>(std::difftime(subkey.expirationTime(), t));
    return {secsTillExpiry <= 0 ? Expiration::Expired : Expiration::Expires,
            std::chrono::duration_cast<Kleo::chrono::days>(std::chrono::seconds{std::abs(secsTillExpiry)})};
}

void ExpiryCheckerPrivate::checkKeyNearExpiry(const GpgME::Key &key, bool isOwnKey, bool isSigningKey, bool ca, int recur_limit, const GpgME::Key &orig_key)
{
    if (recur_limit <= 0) {
        qCDebug(LIBKLEO_LOG) << "Key chain too long (>100 certs)";
        return;
    }
    const GpgME::Subkey subkey = key.subkey(0);

    const bool newMessage = !alreadyWarnedFingerprints.count(subkey.fingerprint());

    const auto expiration = calculateExpiration(subkey);
    if (expiration.status == Expiration::NeverExpires) {
        return;
    }
    if (expiration.status == Expiration::Expired) {
        const QString msg = key.protocol() == GpgME::OpenPGP ? formatOpenPGPMessage(key, expiration, isOwnKey, isSigningKey)
                                                             : formatSMIMEMessage(key, orig_key, expiration, isOwnKey, isSigningKey, ca);
        alreadyWarnedFingerprints.insert(subkey.fingerprint());
        Q_EMIT q->expiryMessage(key, msg, isOwnKey ? ExpiryChecker::OwnKeyExpired : ExpiryChecker::OtherKeyExpired, newMessage);
    } else {
        const auto threshold = ca ? (key.isRoot() ? rootCertThreshold : chainCertThreshold) : (isOwnKey ? ownKeyThreshold : otherKeyThreshold);
        if (threshold >= Kleo::chrono::days::zero() && expiration.duration <= threshold) {
            const QString msg = key.protocol() == GpgME::OpenPGP ? formatOpenPGPMessage(key, expiration, isOwnKey, isSigningKey)
                                                                 : formatSMIMEMessage(key, orig_key, expiration, isOwnKey, isSigningKey, ca);
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
