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
#include "expirycheckersettings.h"

#include <libkleo/algorithm.h>
#include <libkleo/keycache.h>
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
    ExpiryCheckerPrivate(ExpiryChecker *qq, const ExpiryCheckerSettings &settings_)
        : q{qq}
        , settings{settings_}
    {
    }

    Expiration calculateExpiration(const GpgME::Subkey &key) const;

    void checkKeyNearExpiry(const GpgME::Key &key, ExpiryChecker::CheckFlags flags);

    ExpiryCheckerSettings settings;
    std::set<QByteArray> alreadyWarnedFingerprints;
    std::shared_ptr<TimeProvider> timeProvider;
};

ExpiryChecker::ExpiryChecker(const ExpiryCheckerSettings &settings)
    : d{new ExpiryCheckerPrivate{this, settings}}
{
}

ExpiryChecker::~ExpiryChecker() = default;

ExpiryCheckerSettings ExpiryChecker::settings() const
{
    return d->settings;
}

QString formatOpenPGPMessage(const GpgME::Key &key, Expiration expiration, ExpiryChecker::CheckFlags flags)
{
    const bool isOwnKey = flags & ExpiryChecker::OwnKey;
    const bool isSigningKey = flags & ExpiryChecker::SigningKey;
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

QString formatSMIMEMessage(const GpgME::Key &key, const GpgME::Key &orig_key, Expiration expiration, ExpiryChecker::CheckFlags flags, bool ca)
{
    const bool isOwnKey = flags & ExpiryChecker::OwnKey;
    const bool isSigningKey = flags & ExpiryChecker::SigningKey;
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
                        "<p>expired one day ago.</p>",
                        "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                        "<p>for your S/MIME signing certificate</p><p align=center>%2</p>"
                        "<p>expired %1 days ago.</p>");
                } else if (isOwnKey) {
                    msg = ki18np(
                        "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                        "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                        "<p>expired one day ago.</p>",
                        "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                        "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                        "<p>expired %1 days ago.</p>");
                } else {
                    msg = ki18np(
                        "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                        "<p>for S/MIME certificate</p><p align=center>%2</p>"
                        "<p>expired one day ago.</p>",
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
                    "<p>expired one day ago.</p>",
                    "<p>Your S/MIME signing certificate</p><p align=center>%2</p>"
                    "<p>expired %1 days ago.</p>");
            } else if (isOwnKey) {
                msg = ki18np(
                    "<p>Your S/MIME encryption certificate</p><p align=center>%2</p>"
                    "<p>expired one day ago.</p>",
                    "<p>Your S/MIME encryption certificate</p><p align=center>%2</p>"
                    "<p>expired %1 days ago.</p>");
            } else {
                msg = ki18np(
                    "<p>The S/MIME certificate for</p><p align=center>%2</p>"
                    "<p>expired one day ago.</p>",
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
                    "<p>for your S/MIME signing certificate</p><p align=center>%2</p>"
                    "<p>expires in less than a day.</p>",
                    "<p>The root certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME signing certificate</p><p align=center>%2</p>"
                    "<p>expires in less than %1 days.</p>");
            } else if (isOwnKey) {
                msg = ki18np(
                    "<p>The root certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                    "<p>expires in less than a day.</p>",
                    "<p>The root certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                    "<p>expires in less than %1 days.</p>");
            } else {
                msg = ki18np(
                    "<p>The root certificate</p><p align=center><b>%3</b></p>"
                    "<p>for S/MIME certificate</p><p align=center>%2</p>"
                    "<p>expires in less than a day.</p>",
                    "<p>The root certificate</p><p align=center><b>%3</b></p>"
                    "<p>for S/MIME certificate</p><p align=center>%2</p>"
                    "<p>expires in less than %1 days.</p>");
            }
        } else {
            if (isSigningKey) {
                msg = ki18np(
                    "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME signing certificate</p><p align=center>%2</p>"
                    "<p>expires in less than a day.</p>",
                    "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME signing certificate</p><p align=center>%2</p>"
                    "<p>expires in less than %1 days.</p>");
            } else if (isOwnKey) {
                msg = ki18np(
                    "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                    "<p>expires in less than a day.</p>",
                    "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                    "<p>expires in less than %1 days.</p>");
            } else {
                msg = ki18np(
                    "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                    "<p>for S/MIME certificate</p><p align=center>%2</p>"
                    "<p>expires in less than a day.</p>",
                    "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                    "<p>for S/MIME certificate</p><p align=center>%2</p>"
                    "<p>expires in less than %1 days.</p>");
            }
        }
        return msg.subs(expiration.duration.count() + 1).subs(userCertInfo).subs(Kleo::DN(key.userID(0).id()).prettyDN()).toString();
    }
    if (isSigningKey) {
        msg = ki18np(
            "<p>Your S/MIME signing certificate</p><p align=center>%2</p>"
            "<p>expires in less than a day.</p>",
            "<p>Your S/MIME signing certificate</p><p align=center>%2</p>"
            "<p>expires in less than %1 days.</p>");
    } else if (isOwnKey) {
        msg = ki18np(
            "<p>Your S/MIME encryption certificate</p><p align=center>%2</p>"
            "<p>expires in less than a day.</p>",
            "<p>Your S/MIME encryption certificate</p><p align=center>%2</p>"
            "<p>expires in less than %1 days.</p>");
    } else {
        msg = ki18np(
            "<p>The S/MIME certificate for</p><p align=center>%2</p>"
            "<p>expires in less than a day.</p>",
            "<p>The S/MIME certificate for</p><p align=center>%2</p>"
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

void ExpiryCheckerPrivate::checkKeyNearExpiry(const GpgME::Key &orig_key, ExpiryChecker::CheckFlags flags)
{
    static const int maximumCertificateChainLength = 100;
    const bool isOwnKey = flags & ExpiryChecker::OwnKey;

    // use vector instead of set because certificate chains are usually very short
    std::vector<std::string> checkedCertificates;
    auto key = orig_key;
    for (int chainCount = 0; chainCount < maximumCertificateChainLength; ++chainCount) {
        checkedCertificates.push_back(key.primaryFingerprint());

        const GpgME::Subkey subkey = key.subkey(0);

        const bool newMessage = !alreadyWarnedFingerprints.count(subkey.fingerprint());

        const auto expiration = calculateExpiration(subkey);
        if (expiration.status == Expiration::Expired) {
            const QString msg = key.protocol() == GpgME::OpenPGP //
                ? formatOpenPGPMessage(key, expiration, flags)
                : formatSMIMEMessage(key, orig_key, expiration, flags, chainCount > 0);
            alreadyWarnedFingerprints.insert(subkey.fingerprint());
            Q_EMIT q->expiryMessage(key, msg, isOwnKey ? ExpiryChecker::OwnKeyExpired : ExpiryChecker::OtherKeyExpired, newMessage);
        } else if (expiration.status == Expiration::Expires) {
            const auto threshold = chainCount > 0 //
                ? (key.isRoot() ? settings.rootCertThreshold() : settings.chainCertThreshold()) //
                : (isOwnKey ? settings.ownKeyThreshold() : settings.otherKeyThreshold());
            if (threshold >= Kleo::chrono::days::zero() && expiration.duration <= threshold) {
                const QString msg = key.protocol() == GpgME::OpenPGP //
                    ? formatOpenPGPMessage(key, expiration, flags)
                    : formatSMIMEMessage(key, orig_key, expiration, flags, chainCount > 0);
                alreadyWarnedFingerprints.insert(subkey.fingerprint());
                Q_EMIT q->expiryMessage(key, msg, isOwnKey ? ExpiryChecker::OwnKeyNearExpiry : ExpiryChecker::OtherKeyNearExpiry, newMessage);
            }
        }
        if (!(flags & ExpiryChecker::CheckChain) || key.isRoot() || (key.protocol() != GpgME::CMS)) {
            break;
        }
        const auto keys = KeyCache::instance()->findIssuers(key, KeyCache::NoOption);
        if (keys.empty()) {
            break;
        }
        key = keys.front();
        if (Kleo::contains(checkedCertificates, key.primaryFingerprint())) {
            break; // this certificate was already checked (looks like a circle in the chain)
        }
    }
}

void ExpiryChecker::checkKey(const GpgME::Key &key, CheckFlags flags) const
{
    d->checkKeyNearExpiry(key, flags);
}

void ExpiryChecker::setTimeProviderForTest(const std::shared_ptr<TimeProvider> &timeProvider)
{
    d->timeProvider = timeProvider;
}
