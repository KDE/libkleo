/*
    defaultkeyfilter.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "defaultkeyfilter.h"
#include "utils/compliance.h"

#if GPGMEPP_KEY_HAS_HASCERTIFY_SIGN_ENCRYPT_AUTHENTICATE
#else
#include <libkleo/compat.h>
#endif
#include <libkleo/compliance.h>
#include <libkleo/formatting.h>
#include <libkleo/keyhelpers.h>

#include <functional>
#include <memory>

using namespace GpgME;
using namespace Kleo;

static bool is_card_key(const Key &key)
{
    const std::vector<Subkey> sks = key.subkeys();
    return std::find_if(sks.begin(), sks.end(), std::mem_fn(&Subkey::isCardKey)) != sks.end();
}

class DefaultKeyFilter::Private
{
public:
    Private()
    {
    }

    QColor mFgColor;
    QColor mBgColor;
    QString mName;
    QString mIcon;
    QString mId;
    QString mDescription;
    MatchContexts mMatchContexts = AnyMatchContext;
    unsigned int mSpecificity = 0;
    bool mItalic = false;
    bool mBold = false;
    bool mStrikeOut = false;
    bool mUseFullFont = false;
    QFont mFont;

    TriState mRevoked = DoesNotMatter;
    TriState mExpired = DoesNotMatter;
    TriState mInvalid = DoesNotMatter;
    TriState mDisabled = DoesNotMatter;
    TriState mRoot = DoesNotMatter;
    TriState mCanEncrypt = DoesNotMatter;
    TriState mCanSign = DoesNotMatter;
    TriState mCanCertify = DoesNotMatter;
    TriState mCanAuthenticate = DoesNotMatter;
    TriState mHasEncrypt = DoesNotMatter;
    TriState mHasSign = DoesNotMatter;
    TriState mHasCertify = DoesNotMatter;
    TriState mHasAuthenticate = DoesNotMatter;
    TriState mQualified = DoesNotMatter;
    TriState mCardKey = DoesNotMatter;
    TriState mHasSecret = DoesNotMatter;
    TriState mIsOpenPGP = DoesNotMatter;
    TriState mWasValidated = DoesNotMatter;
    TriState mIsDeVs = DoesNotMatter;
    TriState mBad = DoesNotMatter;
    TriState mValidIfSMIME = DoesNotMatter;

    LevelState mOwnerTrust = LevelDoesNotMatter;
    GpgME::Key::OwnerTrust mOwnerTrustReferenceLevel = Key::OwnerTrust::Unknown;
    LevelState mValidity = LevelDoesNotMatter;
    GpgME::UserID::Validity mValidityReferenceLevel = UserID::Validity::Unknown;
};

DefaultKeyFilter::DefaultKeyFilter()
    : KeyFilter{}
    , d{new Private}
{
}

DefaultKeyFilter::~DefaultKeyFilter() = default;

bool DefaultKeyFilter::matches(const Key &key, MatchContexts contexts) const
{
    if (!(d->mMatchContexts & contexts)) {
        return false;
    }
#ifdef MATCH
#undef MATCH
#endif
#define MATCH(member, method)                                                                                                                                  \
    do {                                                                                                                                                       \
        if (member != DoesNotMatter && key.method() != bool(member == Set)) {                                                                                  \
            return false;                                                                                                                                      \
        }                                                                                                                                                      \
    } while (false)
#define IS_MATCH(what) MATCH(d->m##what, is##what)
#define CAN_MATCH(what) MATCH(d->mCan##what, can##what)
#if GPGMEPP_KEY_HAS_HASCERTIFY_SIGN_ENCRYPT_AUTHENTICATE
#define HAS_MATCH(what) MATCH(d->mHas##what, has##what)
#else
#define HAS_MATCH(what)                                                                                                                                        \
    do {                                                                                                                                                       \
        if (d->mHas##what != DoesNotMatter && Kleo::keyHas##what(key) != bool(d->mHas##what == Set)) {                                                         \
            return false;                                                                                                                                      \
        }                                                                                                                                                      \
    } while (false)
#endif
    IS_MATCH(Revoked);
    IS_MATCH(Expired);
    IS_MATCH(Invalid);
    IS_MATCH(Disabled);
    IS_MATCH(Root);
    CAN_MATCH(Encrypt);
    CAN_MATCH(Sign);
    CAN_MATCH(Certify);
    CAN_MATCH(Authenticate);
    HAS_MATCH(Encrypt);
    HAS_MATCH(Sign);
    HAS_MATCH(Certify);
    HAS_MATCH(Authenticate);
    IS_MATCH(Qualified);
    if (d->mCardKey != DoesNotMatter) {
        if ((d->mCardKey == Set && !is_card_key(key)) || (d->mCardKey == NotSet && is_card_key(key))) {
            return false;
        }
    }
    MATCH(d->mHasSecret, hasSecret);
#undef MATCH
    if (d->mIsOpenPGP != DoesNotMatter && bool(key.protocol() == GpgME::OpenPGP) != bool(d->mIsOpenPGP == Set)) {
        return false;
    }
    if (d->mWasValidated != DoesNotMatter && bool(key.keyListMode() & GpgME::Validate) != bool(d->mWasValidated == Set)) {
        return false;
    }
    if (d->mIsDeVs != DoesNotMatter && bool(DeVSCompliance::keyIsCompliant(key)) != bool(d->mIsDeVs == Set)) {
        return false;
    }
    if (d->mBad != DoesNotMatter &&
        /* This is similar to GPGME::Key::isBad which was introduced in GPGME 1.13.0 */
        bool(key.isNull() || key.isRevoked() || key.isExpired() || key.isDisabled() || key.isInvalid()) != bool(d->mBad == Set)) {
        return false;
    }
    const UserID uid = key.userID(0);
    if ((key.protocol() == GpgME::CMS) //
        && (d->mValidIfSMIME != DoesNotMatter) //
        && (bool(uid.validity() >= UserID::Full) != bool(d->mValidIfSMIME == Set))) {
        return false;
    }
    switch (d->mOwnerTrust) {
    default:
    case LevelDoesNotMatter:
        break;
    case Is:
        if (key.ownerTrust() != d->mOwnerTrustReferenceLevel) {
            return false;
        }
        break;
    case IsNot:
        if (key.ownerTrust() == d->mOwnerTrustReferenceLevel) {
            return false;
        }
        break;
    case IsAtLeast:
        if (static_cast<int>(key.ownerTrust()) < static_cast<int>(d->mOwnerTrustReferenceLevel)) {
            return false;
        }
        break;
    case IsAtMost:
        if (static_cast<int>(key.ownerTrust()) > static_cast<int>(d->mOwnerTrustReferenceLevel)) {
            return false;
        }
        break;
    }
    switch (d->mValidity) {
    default:
    case LevelDoesNotMatter:
        break;
    case Is:
        if (uid.validity() != d->mValidityReferenceLevel) {
            return false;
        }
        break;
    case IsNot:
        if (uid.validity() == d->mValidityReferenceLevel) {
            return false;
        }
        break;
    case IsAtLeast:
        if (static_cast<int>(uid.validity()) < static_cast<int>(d->mValidityReferenceLevel)) {
            return false;
        }
        break;
    case IsAtMost:
        if (static_cast<int>(uid.validity()) > static_cast<int>(d->mValidityReferenceLevel)) {
            return false;
        }
        break;
    }
    return true;
}

bool DefaultKeyFilter::matches(const UserID &userID, MatchContexts contexts) const
{
    if (!(d->mMatchContexts & contexts)) {
        return false;
    }
#ifdef MATCH_KEY
#undef MATCH_KEY
#endif
#define MATCH_KEY(member, method)                                                                                                                              \
    do {                                                                                                                                                       \
        if (member != DoesNotMatter && userID.parent().method() != bool(member == Set)) {                                                                      \
            return false;                                                                                                                                      \
        }                                                                                                                                                      \
    } while (false)
#define IS_MATCH_KEY(what) MATCH_KEY(d->m##what, is##what)
#define CAN_MATCH_KEY(what) MATCH_KEY(d->mCan##what, can##what)
#if GPGMEPP_KEY_HAS_HASCERTIFY_SIGN_ENCRYPT_AUTHENTICATE
#define HAS_MATCH_KEY(what) MATCH_KEY(d->mHas##what, has##what)
#else
#define HAS_MATCH_KEY(what)                                                                                                                                    \
    do {                                                                                                                                                       \
        if (d->mHas##what != DoesNotMatter && Kleo::keyHas##what(userID.parent()) != bool(d->mHas##what == Set)) {                                             \
            return false;                                                                                                                                      \
        }                                                                                                                                                      \
    } while (false)
#endif

#ifdef MATCH
#undef MATCH
#endif
#define MATCH(member, method)                                                                                                                                  \
    do {                                                                                                                                                       \
        if (member != DoesNotMatter && (userID.parent().method() != bool(member == Set) || userID.method() != bool(member == Set))) {                          \
            return false;                                                                                                                                      \
        }                                                                                                                                                      \
    } while (false)
#define IS_MATCH(what) MATCH(d->m##what, is##what)
    IS_MATCH(Revoked);
    IS_MATCH_KEY(Expired);
    // We have to do this manually since there's no UserID::isExpired()
    if (d->mExpired != DoesNotMatter && (userID.parent().isExpired() != bool(d->mExpired == Set) || isExpired(userID) != bool(d->mExpired == Set))) {
        return false;
    }
    IS_MATCH(Invalid);
    IS_MATCH_KEY(Disabled);
    IS_MATCH_KEY(Root);
    CAN_MATCH_KEY(Encrypt);
    CAN_MATCH_KEY(Sign);
    CAN_MATCH_KEY(Certify);
    CAN_MATCH_KEY(Authenticate);
    HAS_MATCH_KEY(Encrypt);
    HAS_MATCH_KEY(Sign);
    HAS_MATCH_KEY(Certify);
    HAS_MATCH_KEY(Authenticate);
    IS_MATCH_KEY(Qualified);
    if (d->mCardKey != DoesNotMatter) {
        if ((d->mCardKey == Set && !is_card_key(userID.parent())) || (d->mCardKey == NotSet && is_card_key(userID.parent()))) {
            return false;
        }
    }
    MATCH_KEY(d->mHasSecret, hasSecret);
#undef MATCH
    if (d->mIsOpenPGP != DoesNotMatter && bool(userID.parent().protocol() == GpgME::OpenPGP) != bool(d->mIsOpenPGP == Set)) {
        return false;
    }
    if (d->mWasValidated != DoesNotMatter && bool(userID.parent().keyListMode() & GpgME::Validate) != bool(d->mWasValidated == Set)) {
        return false;
    }
    if (d->mIsDeVs != DoesNotMatter && bool(DeVSCompliance::userIDIsCompliant(userID)) != bool(d->mIsDeVs == Set)) {
        return false;
    }
    if (d->mBad != DoesNotMatter &&
        /* This is similar to GPGME::Key::isBad which was introduced in GPGME 1.13.0 */
        bool(userID.parent().isNull() || userID.isNull() || userID.parent().isRevoked() || userID.isRevoked() || userID.parent().isExpired()
             || userID.parent().isDisabled() || userID.parent().isInvalid() || userID.isInvalid())
            != bool(d->mBad == Set)) {
        return false;
    }
    if ((userID.parent().protocol() == GpgME::CMS) //
        && (d->mValidIfSMIME != DoesNotMatter) //
        && (bool(userID.validity() >= UserID::Full) != bool(d->mValidIfSMIME == Set))) {
        return false;
    }
    switch (d->mOwnerTrust) {
    default:
    case LevelDoesNotMatter:
        break;
    case Is:
        if (userID.parent().ownerTrust() != d->mOwnerTrustReferenceLevel) {
            return false;
        }
        break;
    case IsNot:
        if (userID.parent().ownerTrust() == d->mOwnerTrustReferenceLevel) {
            return false;
        }
        break;
    case IsAtLeast:
        if (static_cast<int>(userID.parent().ownerTrust()) < static_cast<int>(d->mOwnerTrustReferenceLevel)) {
            return false;
        }
        break;
    case IsAtMost:
        if (static_cast<int>(userID.parent().ownerTrust()) > static_cast<int>(d->mOwnerTrustReferenceLevel)) {
            return false;
        }
        break;
    }
    switch (d->mValidity) {
    default:
    case LevelDoesNotMatter:
        break;
    case Is:
        if (userID.validity() != d->mValidityReferenceLevel) {
            return false;
        }
        break;
    case IsNot:
        if (userID.validity() == d->mValidityReferenceLevel) {
            return false;
        }
        break;
    case IsAtLeast:
        if (static_cast<int>(userID.validity()) < static_cast<int>(d->mValidityReferenceLevel)) {
            return false;
        }
        break;
    case IsAtMost:
        if (static_cast<int>(userID.validity()) > static_cast<int>(d->mValidityReferenceLevel)) {
            return false;
        }
        break;
    }
    return true;
}

KeyFilter::FontDescription DefaultKeyFilter::fontDescription() const
{
    if (d->mUseFullFont) {
        return FontDescription::create(font(), bold(), italic(), strikeOut());
    } else {
        return FontDescription::create(bold(), italic(), strikeOut());
    }
}

void DefaultKeyFilter::setFgColor(const QColor &value)
{
    d->mFgColor = value;
}

void DefaultKeyFilter::setBgColor(const QColor &value)
{
    d->mBgColor = value;
}

void DefaultKeyFilter::setName(const QString &value)
{
    d->mName = value;
}

void DefaultKeyFilter::setIcon(const QString &value)
{
    d->mIcon = value;
}

void DefaultKeyFilter::setId(const QString &value)
{
    d->mId = value;
}

void DefaultKeyFilter::setMatchContexts(MatchContexts value)
{
    d->mMatchContexts = value;
}

void DefaultKeyFilter::setSpecificity(unsigned int value)
{
    d->mSpecificity = value;
}

void DefaultKeyFilter::setItalic(bool value)
{
    d->mItalic = value;
}

void DefaultKeyFilter::setBold(bool value)
{
    d->mBold = value;
}

void DefaultKeyFilter::setStrikeOut(bool value)
{
    d->mStrikeOut = value;
}

void DefaultKeyFilter::setUseFullFont(bool value)
{
    d->mUseFullFont = value;
}

void DefaultKeyFilter::setFont(const QFont &value)
{
    d->mFont = value;
}

void DefaultKeyFilter::setRevoked(DefaultKeyFilter::TriState value)
{
    d->mRevoked = value;
}

void DefaultKeyFilter::setExpired(DefaultKeyFilter::TriState value)
{
    d->mExpired = value;
}

void DefaultKeyFilter::setInvalid(DefaultKeyFilter::TriState value)
{
    d->mInvalid = value;
}

void DefaultKeyFilter::setDisabled(DefaultKeyFilter::TriState value)
{
    d->mDisabled = value;
}

void DefaultKeyFilter::setRoot(DefaultKeyFilter::TriState value)
{
    d->mRoot = value;
}

void DefaultKeyFilter::setCanEncrypt(DefaultKeyFilter::TriState value)
{
    d->mCanEncrypt = value;
}

void DefaultKeyFilter::setCanSign(DefaultKeyFilter::TriState value)
{
    d->mCanSign = value;
}

void DefaultKeyFilter::setCanCertify(DefaultKeyFilter::TriState value)
{
    d->mCanCertify = value;
}

void DefaultKeyFilter::setCanAuthenticate(DefaultKeyFilter::TriState value)
{
    d->mCanAuthenticate = value;
}

void DefaultKeyFilter::setHasEncrypt(DefaultKeyFilter::TriState value)
{
    d->mHasEncrypt = value;
}

void DefaultKeyFilter::setHasSign(DefaultKeyFilter::TriState value)
{
    d->mHasSign = value;
}

void DefaultKeyFilter::setHasCertify(DefaultKeyFilter::TriState value)
{
    d->mHasCertify = value;
}

void DefaultKeyFilter::setHasAuthenticate(DefaultKeyFilter::TriState value)
{
    d->mHasAuthenticate = value;
}

void DefaultKeyFilter::setQualified(DefaultKeyFilter::TriState value)
{
    d->mQualified = value;
}

void DefaultKeyFilter::setCardKey(DefaultKeyFilter::TriState value)
{
    d->mCardKey = value;
}

void DefaultKeyFilter::setHasSecret(DefaultKeyFilter::TriState value)
{
    d->mHasSecret = value;
}

void DefaultKeyFilter::setIsOpenPGP(DefaultKeyFilter::TriState value)
{
    d->mIsOpenPGP = value;
}

void DefaultKeyFilter::setWasValidated(DefaultKeyFilter::TriState value)
{
    d->mWasValidated = value;
}

void DefaultKeyFilter::setOwnerTrust(DefaultKeyFilter::LevelState value)
{
    d->mOwnerTrust = value;
}

void DefaultKeyFilter::setOwnerTrustReferenceLevel(GpgME::Key::OwnerTrust value)
{
    d->mOwnerTrustReferenceLevel = value;
}

void DefaultKeyFilter::setValidity(DefaultKeyFilter::LevelState value)
{
    d->mValidity = value;
}

void DefaultKeyFilter::setValidityReferenceLevel(GpgME::UserID::Validity value)
{
    d->mValidityReferenceLevel = value;
}

void DefaultKeyFilter::setIsDeVs(DefaultKeyFilter::TriState value)
{
    d->mIsDeVs = value;
}

void DefaultKeyFilter::setIsBad(DefaultKeyFilter::TriState value)
{
    d->mBad = value;
}

void DefaultKeyFilter::setValidIfSMIME(DefaultKeyFilter::TriState value)
{
    d->mValidIfSMIME = value;
}

QColor DefaultKeyFilter::fgColor() const
{
    return d->mFgColor;
}

QColor DefaultKeyFilter::bgColor() const
{
    return d->mBgColor;
}

QString DefaultKeyFilter::name() const
{
    return d->mName;
}

QString DefaultKeyFilter::icon() const
{
    return d->mIcon;
}

QString DefaultKeyFilter::id() const
{
    return d->mId;
}

QFont DefaultKeyFilter::font() const
{
    return d->mFont;
}

KeyFilter::MatchContexts DefaultKeyFilter::availableMatchContexts() const
{
    return d->mMatchContexts;
}

unsigned int DefaultKeyFilter::specificity() const
{
    return d->mSpecificity;
}

bool DefaultKeyFilter::italic() const
{
    return d->mItalic;
}

bool DefaultKeyFilter::bold() const
{
    return d->mBold;
}

bool DefaultKeyFilter::strikeOut() const
{
    return d->mStrikeOut;
}

bool DefaultKeyFilter::useFullFont() const
{
    return d->mUseFullFont;
}

DefaultKeyFilter::TriState DefaultKeyFilter::revoked() const
{
    return d->mRevoked;
}

DefaultKeyFilter::TriState DefaultKeyFilter::expired() const
{
    return d->mExpired;
}

DefaultKeyFilter::TriState DefaultKeyFilter::invalid() const
{
    return d->mInvalid;
}

DefaultKeyFilter::TriState DefaultKeyFilter::disabled() const
{
    return d->mDisabled;
}

DefaultKeyFilter::TriState DefaultKeyFilter::root() const
{
    return d->mRoot;
}

DefaultKeyFilter::TriState DefaultKeyFilter::canEncrypt() const
{
    return d->mCanEncrypt;
}

DefaultKeyFilter::TriState DefaultKeyFilter::canSign() const
{
    return d->mCanSign;
}

DefaultKeyFilter::TriState DefaultKeyFilter::canCertify() const
{
    return d->mCanCertify;
}

DefaultKeyFilter::TriState DefaultKeyFilter::canAuthenticate() const
{
    return d->mCanAuthenticate;
}

DefaultKeyFilter::TriState DefaultKeyFilter::hasEncrypt() const
{
    return d->mHasEncrypt;
}

DefaultKeyFilter::TriState DefaultKeyFilter::hasSign() const
{
    return d->mHasSign;
}

DefaultKeyFilter::TriState DefaultKeyFilter::hasCertify() const
{
    return d->mHasCertify;
}

DefaultKeyFilter::TriState DefaultKeyFilter::hasAuthenticate() const
{
    return d->mHasAuthenticate;
}

DefaultKeyFilter::TriState DefaultKeyFilter::qualified() const
{
    return d->mQualified;
}

DefaultKeyFilter::TriState DefaultKeyFilter::cardKey() const
{
    return d->mCardKey;
}

DefaultKeyFilter::TriState DefaultKeyFilter::hasSecret() const
{
    return d->mHasSecret;
}

DefaultKeyFilter::TriState DefaultKeyFilter::isOpenPGP() const
{
    return d->mIsOpenPGP;
}

DefaultKeyFilter::TriState DefaultKeyFilter::wasValidated() const
{
    return d->mWasValidated;
}

DefaultKeyFilter::LevelState DefaultKeyFilter::ownerTrust() const
{
    return d->mOwnerTrust;
}

GpgME::Key::OwnerTrust DefaultKeyFilter::ownerTrustReferenceLevel() const
{
    return d->mOwnerTrustReferenceLevel;
}

DefaultKeyFilter::LevelState DefaultKeyFilter::validity() const
{
    return d->mValidity;
}

GpgME::UserID::Validity DefaultKeyFilter::validityReferenceLevel() const
{
    return d->mValidityReferenceLevel;
}

DefaultKeyFilter::TriState DefaultKeyFilter::isDeVS() const
{
    return d->mIsDeVs;
}

DefaultKeyFilter::TriState DefaultKeyFilter::isBad() const
{
    return d->mBad;
}

DefaultKeyFilter::TriState DefaultKeyFilter::validIfSMIME() const
{
    return d->mValidIfSMIME;
}

QString DefaultKeyFilter::description() const
{
    return d->mDescription;
}

void DefaultKeyFilter::setDescription(const QString &description)
{
    d->mDescription = description;
}
