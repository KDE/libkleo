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

class Kleo::ExpiryCheckerPrivate
{
    Kleo::ExpiryChecker *q;

public:
    ExpiryCheckerPrivate(ExpiryChecker *qq, const ExpiryCheckerSettings &settings_)
        : q{qq}
        , settings{settings_}
    {
    }

    ExpiryChecker::Expiration calculateExpiration(const GpgME::Subkey &subkey) const;
    ExpiryChecker::Expiration checkForExpiration(const GpgME::Key &key, Kleo::chrono::days threshold, ExpiryChecker::CheckFlags flags) const;

    ExpiryChecker::Result checkKeyNearExpiry(const GpgME::Key &key, ExpiryChecker::CheckFlags flags);

    ExpiryCheckerSettings settings;
    std::set<QByteArray> alreadyWarnedFingerprints;
    std::shared_ptr<TimeProvider> timeProvider;
};

ExpiryChecker::ExpiryChecker(const ExpiryCheckerSettings &settings, QObject *parent)
    : QObject{parent}
    , d{new ExpiryCheckerPrivate{this, settings}}
{
}

ExpiryChecker::~ExpiryChecker() = default;

ExpiryCheckerSettings ExpiryChecker::settings() const
{
    return d->settings;
}

QString formatOpenPGPMessage(ExpiryChecker::Expiration expiration, ExpiryChecker::CheckFlags flags)
{
    const GpgME::Key key = expiration.certificate;
    const bool isOwnKey = flags & ExpiryChecker::OwnKey;
    const bool isSigningKey = flags & ExpiryChecker::SigningKey;
    const auto keyInfo = ki18nc("<b>User ID of key</b> (Key ID key ID of key in hex notation)", "<b>%1</b> (Key ID 0x%2)")
                             .subs(QString::fromUtf8(key.userID(0).id()))
                             .subs(QString::fromLatin1(key.keyID()));
    if (expiration.status == ExpiryChecker::Expired) {
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
            msg = ki18np("<p>Your OpenPGP signing key</p><p align=center>%2</p><p>expired yesterday.</p>",
                         "<p>Your OpenPGP signing key</p><p align=center>%2</p><p>expired %1 days ago.</p>");
        } else if (isOwnKey) {
            msg = ki18np("<p>Your OpenPGP encryption key</p><p align=center>%2</p><p>expired yesterday.</p>",
                         "<p>Your OpenPGP encryption key</p><p align=center>%2</p><p>expired %1 days ago.</p>");
        } else {
            msg = ki18np("<p>The OpenPGP key for</p><p align=center>%2</p><p>expired yesterday.</p>",
                         "<p>The OpenPGP key for</p><p align=center>%2</p><p>expired %1 days ago.</p>");
        }
        return msg.subs(expiration.duration.count()).subs(keyInfo).toString();
    }
    qCDebug(LIBKLEO_LOG) << "Key" << key << "expires in" << expiration.duration.count() << "days";
    if (expiration.duration.count() == 0) {
        KLocalizedString msg;
        if (isSigningKey) {
            msg = ki18n("<p>Your OpenPGP signing key</p><p align=center>%1</p><p>expires today.</p>");
        } else if (isOwnKey) {
            msg = ki18n("<p>Your OpenPGP encryption key</p><p align=center>%1</p><p>expires today.</p>");
        } else {
            msg = ki18n("<p>The OpenPGP key for</p><p align=center>%1</p><p>expires today.</p>");
        }
        return msg.subs(keyInfo).toString();
    }
    KLocalizedString msg;
    if (isSigningKey) {
        msg = ki18np("<p>Your OpenPGP signing key</p><p align=center>%2</p><p>expires tomorrow.</p>",
                     "<p>Your OpenPGP signing key</p><p align=center>%2</p><p>expires in %1 days.</p>");
    } else if (isOwnKey) {
        msg = ki18np("<p>Your OpenPGP encryption key</p><p align=center>%2</p><p>expires tomorrow.</p>",
                     "<p>Your OpenPGP encryption key</p><p align=center>%2</p><p>expires in %1 days.</p>");
    } else {
        msg = ki18np("<p>The OpenPGP key for</p><p align=center>%2</p><p>expires tomorrow.</p>",
                     "<p>The OpenPGP key for</p><p align=center>%2</p><p>expires in %1 days.</p>");
    }
    return msg.subs(expiration.duration.count()).subs(keyInfo).toString();
}

QString formatSMIMEMessage(const GpgME::Key &orig_key, ExpiryChecker::Expiration expiration, ExpiryChecker::CheckFlags flags, bool ca)
{
    const GpgME::Key key = expiration.certificate;
    const bool isOwnKey = flags & ExpiryChecker::OwnKey;
    const bool isSigningKey = flags & ExpiryChecker::SigningKey;
    const auto userCert = orig_key.isNull() ? key : orig_key;
    const auto userCertInfo = ki18nc("<b>User ID of certificate</b> (serial number serial no. of certificate)", "<b>%1</b> (serial number %2)")
                                  .subs(Kleo::DN(userCert.userID(0).id()).prettyDN())
                                  .subs(QString::fromLatin1(userCert.issuerSerial()));
    if (expiration.status == ExpiryChecker::Expired) {
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
                        "<p>expired yesterday.</p>",
                        "<p>The root certificate</p><p align=center><b>%3</b></p>"
                        "<p>for your S/MIME signing certificate</p><p align=center>%2</p>"
                        "<p>expired %1 days ago.</p>");
                } else if (isOwnKey) {
                    msg = ki18np(
                        "<p>The root certificate</p><p align=center><b>%3</b></p>"
                        "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                        "<p>expired yesterday.</p>",
                        "<p>The root certificate</p><p align=center><b>%3</b></p>"
                        "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                        "<p>expired %1 days ago.</p>");
                } else {
                    msg = ki18np(
                        "<p>The root certificate</p><p align=center><b>%3</b></p>"
                        "<p>for S/MIME certificate</p><p align=center>%2</p>"
                        "<p>expired yesterday.</p>",
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
                        "<p>expired yesterday.</p>",
                        "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                        "<p>for your S/MIME signing certificate</p><p align=center>%2</p>"
                        "<p>expired %1 days ago.</p>");
                } else if (isOwnKey) {
                    msg = ki18np(
                        "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                        "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                        "<p>expired yesterday.</p>",
                        "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                        "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                        "<p>expired %1 days ago.</p>");
                } else {
                    msg = ki18np(
                        "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                        "<p>for S/MIME certificate</p><p align=center>%2</p>"
                        "<p>expired yesterday.</p>",
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
                msg = ki18np("<p>Your S/MIME signing certificate</p><p align=center>%2</p><p>expired yesterday.</p>",
                             "<p>Your S/MIME signing certificate</p><p align=center>%2</p><p>expired %1 days ago.</p>");
            } else if (isOwnKey) {
                msg = ki18np("<p>Your S/MIME encryption certificate</p><p align=center>%2</p><p>expired yesterday.</p>",
                             "<p>Your S/MIME encryption certificate</p><p align=center>%2</p><p>expired %1 days ago.</p>");
            } else {
                msg = ki18np("<p>The S/MIME certificate for</p><p align=center>%2</p><p>expired yesterday.</p>",
                             "<p>The S/MIME certificate for</p><p align=center>%2</p><p>expired %1 days ago.</p>");
            }
            return msg.subs(expiration.duration.count()).subs(userCertInfo).toString();
        }
    }
    qCDebug(LIBKLEO_LOG) << "Certificate" << key << "expires in" << expiration.duration.count() << "days";
    if (ca) {
        if (key.isRoot()) {
            if (expiration.duration.count() == 0) {
                KLocalizedString msg;
                if (isSigningKey) {
                    msg = ki18n(
                        "<p>The root certificate</p><p align=center><b>%3</b></p>"
                        "<p>for your S/MIME signing certificate</p><p align=center>%2</p>"
                        "<p>expires today.</p>");
                } else if (isOwnKey) {
                    msg = ki18n(
                        "<p>The root certificate</p><p align=center><b>%3</b></p>"
                        "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                        "<p>expires today.</p>");
                } else {
                    msg = ki18n(
                        "<p>The root certificate</p><p align=center><b>%3</b></p>"
                        "<p>for S/MIME certificate</p><p align=center>%2</p>"
                        "<p>expires today.</p>");
                }
                return msg.subs(userCertInfo).subs(Kleo::DN(key.userID(0).id()).prettyDN()).toString();
            }
            KLocalizedString msg;
            if (isSigningKey) {
                msg = ki18np(
                    "<p>The root certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME signing certificate</p><p align=center>%2</p>"
                    "<p>expires tomorrow.</p>",
                    "<p>The root certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME signing certificate</p><p align=center>%2</p>"
                    "<p>expires in %1 days.</p>");
            } else if (isOwnKey) {
                msg = ki18np(
                    "<p>The root certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                    "<p>expires tomorrow.</p>",
                    "<p>The root certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                    "<p>expires in %1 days.</p>");
            } else {
                msg = ki18np(
                    "<p>The root certificate</p><p align=center><b>%3</b></p>"
                    "<p>for S/MIME certificate</p><p align=center>%2</p>"
                    "<p>expires tomorrow.</p>",
                    "<p>The root certificate</p><p align=center><b>%3</b></p>"
                    "<p>for S/MIME certificate</p><p align=center>%2</p>"
                    "<p>expires in %1 days.</p>");
            }
            return msg.subs(expiration.duration.count()).subs(userCertInfo).subs(Kleo::DN(key.userID(0).id()).prettyDN()).toString();
        }
        if (expiration.duration.count() == 0) {
            KLocalizedString msg;
            if (isSigningKey) {
                msg = ki18n(
                    "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME signing certificate</p><p align=center>%2</p>"
                    "<p>expires today.</p>");
            } else if (isOwnKey) {
                msg = ki18n(
                    "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                    "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                    "<p>expires today.</p>");
            } else {
                msg = ki18n(
                    "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                    "<p>for S/MIME certificate</p><p align=center>%2</p>"
                    "<p>expires today.</p>");
            }
        }
        KLocalizedString msg;
        if (isSigningKey) {
            msg = ki18np(
                "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                "<p>for your S/MIME signing certificate</p><p align=center>%2</p>"
                "<p>expires tomorrow.</p>",
                "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                "<p>for your S/MIME signing certificate</p><p align=center>%2</p>"
                "<p>expires in %1 days.</p>");
        } else if (isOwnKey) {
            msg = ki18np(
                "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                "<p>expires tomorrow.</p>",
                "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                "<p>for your S/MIME encryption certificate</p><p align=center>%2</p>"
                "<p>expires in %1 days.</p>");
        } else {
            msg = ki18np(
                "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                "<p>for S/MIME certificate</p><p align=center>%2</p>"
                "<p>expires tomorrow.</p>",
                "<p>The intermediate CA certificate</p><p align=center><b>%3</b></p>"
                "<p>for S/MIME certificate</p><p align=center>%2</p>"
                "<p>expires in %1 days.</p>");
        }
        return msg.subs(expiration.duration.count()).subs(userCertInfo).subs(Kleo::DN(key.userID(0).id()).prettyDN()).toString();
    }
    if (expiration.duration.count() == 0) {
        KLocalizedString msg;
        if (isSigningKey) {
            msg = ki18n("<p>Your S/MIME signing certificate</p><p align=center>%2</p><p>expires today.</p>");
        } else if (isOwnKey) {
            msg = ki18n("<p>Your S/MIME encryption certificate</p><p align=center>%2</p><p>expires today.</p>");
        } else {
            msg = ki18n("<p>The S/MIME certificate for</p><p align=center>%2</p><p>expires today.</p>");
        }
        return msg.subs(userCertInfo).toString();
    }
    KLocalizedString msg;
    if (isSigningKey) {
        msg = ki18np(
            "<p>Your S/MIME signing certificate</p><p align=center>%2</p>"
            "<p>expires tomorrow.</p>",
            "<p>Your S/MIME signing certificate</p><p align=center>%2</p>"
            "<p>expires in %1 days.</p>");
    } else if (isOwnKey) {
        msg = ki18np(
            "<p>Your S/MIME encryption certificate</p><p align=center>%2</p>"
            "<p>expires tomorrow.</p>",
            "<p>Your S/MIME encryption certificate</p><p align=center>%2</p>"
            "<p>expires in %1 days.</p>");
    } else {
        msg = ki18np(
            "<p>The S/MIME certificate for</p><p align=center>%2</p>"
            "<p>expires tomorrow.</p>",
            "<p>The S/MIME certificate for</p><p align=center>%2</p>"
            "<p>expires in %1 days.</p>");
    }
    return msg.subs(expiration.duration.count()).subs(userCertInfo).toString();
}

static GpgME::Subkey findBestSubkey(const GpgME::Key &key, ExpiryChecker::CheckFlags usageFlags)
{
    // find the subkey with the latest expiration date for the given usage flags
    if (!(usageFlags & ExpiryChecker::UsageMask)) {
        // return primary key if no specific usage is specified (as for chain certificates)
        return key.subkey(0);
    }
    GpgME::Subkey result;
    for (unsigned int i = 0; i < key.numSubkeys(); ++i) {
        const auto subkey = key.subkey(i);
        if (subkey.isRevoked() || subkey.isInvalid() || subkey.isDisabled()) {
            // unusable subkey
            continue;
        }
        if (((usageFlags & ExpiryChecker::EncryptionKey) && !subkey.canEncrypt()) //
            || ((usageFlags & ExpiryChecker::SigningKey) && !subkey.canSign()) //
            || ((usageFlags & ExpiryChecker::CertificationKey) && !subkey.canCertify())) {
            // unsuitable subkey for requested usage
            continue;
        }
        if (subkey.neverExpires()) {
            // stop looking for the best subkey if we found a suitable subkey that doesn't expire;
            // return the primary key because a non-expiring subkey inherits the primary key's expiration
            return key.subkey(0);
        }
        if (quint32(subkey.expirationTime()) > quint32(result.expirationTime())) {
            result = subkey;
        }
    }
    return result;
}

ExpiryChecker::Expiration ExpiryCheckerPrivate::calculateExpiration(const GpgME::Subkey &subkey) const
{
    if (subkey.neverExpires()) {
        return {subkey.parent(), ExpiryChecker::NotNearExpiry, Kleo::chrono::days::zero()};
    }
    const qint64 currentTime = timeProvider ? timeProvider->currentTime() : QDateTime::currentSecsSinceEpoch();
    const auto currentDate = timeProvider ? timeProvider->currentDate() : QDate::currentDate();
    const auto timeSpec = timeProvider ? timeProvider->timeSpec() : Qt::LocalTime;
    // interpret the expiration time as unsigned 32-bit value if it's negative; gpg also uses uint32 internally
    const qint64 expirationTime = qint64(subkey.expirationTime() < 0 ? quint32(subkey.expirationTime()) : subkey.expirationTime());
    const auto expirationDate = QDateTime::fromSecsSinceEpoch(expirationTime, timeSpec).date();
    if (expirationTime <= currentTime) {
        return {subkey.parent(), ExpiryChecker::Expired, Kleo::chrono::days{expirationDate.daysTo(currentDate)}};
    } else {
        return {subkey.parent(), ExpiryChecker::ExpiresSoon, Kleo::chrono::days{currentDate.daysTo(expirationDate)}};
    }
}

ExpiryChecker::Expiration ExpiryCheckerPrivate::checkForExpiration(const GpgME::Key &key, //
                                                                   Kleo::chrono::days threshold,
                                                                   ExpiryChecker::CheckFlags usageFlags) const
{
    const auto subkey = findBestSubkey(key, usageFlags);
    if (subkey.isNull()) {
        return {key, ExpiryChecker::NoSuitableSubkey, {}};
    }
    ExpiryChecker::Expiration expiration = calculateExpiration(subkey);
    if ((expiration.status == ExpiryChecker::ExpiresSoon) && (expiration.duration > threshold)) {
        // key expires, but not too soon
        expiration.status = ExpiryChecker::NotNearExpiry;
    }
    return expiration;
}

ExpiryChecker::Result ExpiryCheckerPrivate::checkKeyNearExpiry(const GpgME::Key &orig_key, ExpiryChecker::CheckFlags flags)
{
    static const int maximumCertificateChainLength = 100;
    const bool isOwnKey = flags & ExpiryChecker::OwnKey;

    ExpiryChecker::Result result;
    result.checkFlags = flags;
    result.expiration.certificate = orig_key;

    // use vector instead of set because certificate chains are usually very short
    std::vector<std::string> checkedCertificates;
    auto key = orig_key;
    for (int chainCount = 0; chainCount < maximumCertificateChainLength; ++chainCount) {
        checkedCertificates.push_back(key.primaryFingerprint());

        const GpgME::Subkey subkey = key.subkey(0);

        const bool newMessage = !alreadyWarnedFingerprints.count(subkey.fingerprint());

        const auto threshold = chainCount > 0 //
            ? (key.isRoot() ? settings.rootCertThreshold() : settings.chainCertThreshold()) //
            : (isOwnKey ? settings.ownKeyThreshold() : settings.otherKeyThreshold());
        const auto usageFlags = (chainCount == 0) ? (flags & ExpiryChecker::UsageMask) : ExpiryChecker::CheckFlags{};
        const auto expiration = checkForExpiration(key, threshold, usageFlags);
        if (chainCount == 0) {
            result.expiration = expiration;
        } else if (expiration.status != ExpiryChecker::NotNearExpiry) {
            result.chainExpiration.push_back(expiration);
        }
        if (expiration.status == ExpiryChecker::Expired) {
            const QString msg = key.protocol() == GpgME::OpenPGP //
                ? formatOpenPGPMessage(expiration, flags)
                : formatSMIMEMessage(orig_key, expiration, flags, chainCount > 0);
            alreadyWarnedFingerprints.insert(subkey.fingerprint());
            Q_EMIT q->expiryMessage(key, msg, isOwnKey ? ExpiryChecker::OwnKeyExpired : ExpiryChecker::OtherKeyExpired, newMessage);
        } else if (expiration.status == ExpiryChecker::ExpiresSoon) {
            const QString msg = key.protocol() == GpgME::OpenPGP //
                ? formatOpenPGPMessage(expiration, flags)
                : formatSMIMEMessage(orig_key, expiration, flags, chainCount > 0);
            alreadyWarnedFingerprints.insert(subkey.fingerprint());
            Q_EMIT q->expiryMessage(key, msg, isOwnKey ? ExpiryChecker::OwnKeyNearExpiry : ExpiryChecker::OtherKeyNearExpiry, newMessage);
        } else if (expiration.status == ExpiryChecker::NoSuitableSubkey) {
            break;
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
    return result;
}

ExpiryChecker::Result ExpiryChecker::checkKey(const GpgME::Key &key, CheckFlags flags) const
{
    if (key.isNull()) {
        qWarning(LIBKLEO_LOG) << __func__ << "called with null key";
        return {flags, {key, InvalidKey, {}}, {}};
    }
    if (!(flags & UsageMask)) {
        qWarning(LIBKLEO_LOG) << __func__ << "called with invalid flags:" << flags;
        return {flags, {key, InvalidCheckFlags, {}}, {}};
    }
    return d->checkKeyNearExpiry(key, flags);
}

void ExpiryChecker::setTimeProviderForTest(const std::shared_ptr<TimeProvider> &timeProvider)
{
    d->timeProvider = timeProvider;
}

#include "moc_expirychecker.cpp"
