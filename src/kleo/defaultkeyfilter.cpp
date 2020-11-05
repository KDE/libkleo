/*
    defaultkeyfilter.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "defaultkeyfilter.h"

#include "utils/formatting.h"

#include <functional>
#include <memory>

using namespace GpgME;
using namespace Kleo;

static bool is_card_key(const Key &key)
{
    const std::vector<Subkey> sks = key.subkeys();
    return std::find_if(sks.begin(), sks.end(),
                        std::mem_fn(&Subkey::isCardKey)) != sks.end();
}

class DefaultKeyFilter::Private
{

public:
    Private() :
        mMatchContexts(AnyMatchContext),
        mRevoked(DoesNotMatter),
        mExpired(DoesNotMatter),
        mInvalid(DoesNotMatter),
        mDisabled(DoesNotMatter),
        mRoot(DoesNotMatter),
        mCanEncrypt(DoesNotMatter),
        mCanSign(DoesNotMatter),
        mCanCertify(DoesNotMatter),
        mCanAuthenticate(DoesNotMatter),
        mQualified(DoesNotMatter),
        mCardKey(DoesNotMatter),
        mHasSecret(DoesNotMatter),
        mIsOpenPGP(DoesNotMatter),
        mWasValidated(DoesNotMatter),
        mIsDeVs(DoesNotMatter),
        mBad(DoesNotMatter),
        mOwnerTrust(LevelDoesNotMatter),
        mOwnerTrustReferenceLevel(Key::Unknown),
        mValidity(LevelDoesNotMatter),
        mValidityReferenceLevel(UserID::Unknown)
    {}
    QColor mFgColor, mBgColor;
    QString mName;
    QString mIcon;
    QString mId;
    MatchContexts mMatchContexts;
    unsigned int mSpecificity = 0;
    bool mItalic = false;
    bool mBold = false;
    bool mStrikeOut = false;
    bool mUseFullFont = false;
    QFont mFont;

    TriState mRevoked;
    TriState mExpired;
    TriState mInvalid;
    TriState mDisabled;
    TriState mRoot;
    TriState mCanEncrypt;
    TriState mCanSign;
    TriState mCanCertify;
    TriState mCanAuthenticate;
    TriState mQualified;
    TriState mCardKey;
    TriState mHasSecret;
    TriState mIsOpenPGP;
    TriState mWasValidated;
    TriState mIsDeVs;
    TriState mBad;

    LevelState mOwnerTrust;
    GpgME::Key::OwnerTrust mOwnerTrustReferenceLevel;
    LevelState mValidity;
    GpgME::UserID::Validity mValidityReferenceLevel;

};

DefaultKeyFilter::DefaultKeyFilter()
    : KeyFilter(),
      d_ptr(new Private())
{
}

DefaultKeyFilter::~DefaultKeyFilter() {}

bool DefaultKeyFilter::matches(const Key &key, MatchContexts contexts) const
{
    if (!(d_ptr->mMatchContexts & contexts)) {
        return false;
    }
#ifdef MATCH
#undef MATCH
#endif
#define MATCH(member,method) \
    if ( member != DoesNotMatter && key.method() != bool( member == Set ) ) \
        return false
#define IS_MATCH(what) MATCH( d_ptr->m##what, is##what )
#define CAN_MATCH(what) MATCH( d_ptr->mCan##what, can##what )
    IS_MATCH(Revoked);
    IS_MATCH(Expired);
    IS_MATCH(Invalid);
    IS_MATCH(Disabled);
    IS_MATCH(Root);
    CAN_MATCH(Encrypt);
    CAN_MATCH(Sign);
    CAN_MATCH(Certify);
    CAN_MATCH(Authenticate);
    IS_MATCH(Qualified);
    if (d_ptr->mCardKey != DoesNotMatter)
        if ((d_ptr->mCardKey == Set    && !is_card_key(key)) ||
                (d_ptr->mCardKey == NotSet &&  is_card_key(key))) {
            return false;
        }
    MATCH(d_ptr->mHasSecret, hasSecret);
#undef MATCH
    if (d_ptr->mIsOpenPGP != DoesNotMatter &&
            bool(key.protocol() == GpgME::OpenPGP) != bool(d_ptr->mIsOpenPGP == Set)) {
        return false;
    }
    if (d_ptr->mWasValidated != DoesNotMatter &&
            bool(key.keyListMode() & GpgME::Validate) != bool(d_ptr->mWasValidated == Set)) {
        return false;
    }
    if (d_ptr->mIsDeVs != DoesNotMatter &&
            bool(Formatting::uidsHaveFullValidity(key) && Formatting::isKeyDeVs(key)) != bool(d_ptr->mIsDeVs == Set)) {
        return false;
    }
    if (d_ptr->mBad != DoesNotMatter &&
        /* This is similar to GPGME::Key::isBad which was introduced in GPGME 1.13.0 */
        bool(key.isNull() || key.isRevoked() || key.isExpired() || key.isDisabled() || key.isInvalid()) != bool(d_ptr->mBad == Set)) {
        return false;
    }
    switch (d_ptr->mOwnerTrust) {
    default:
    case LevelDoesNotMatter:
        break;
    case Is:
        if (key.ownerTrust() != d_ptr->mOwnerTrustReferenceLevel) {
            return false;
        }
        break;
    case IsNot:
        if (key.ownerTrust() == d_ptr->mOwnerTrustReferenceLevel) {
            return false;
        }
        break;
    case IsAtLeast:
        if (static_cast<int>(key.ownerTrust()) < static_cast<int>(d_ptr->mOwnerTrustReferenceLevel)) {
            return false;
        }
        break;
    case IsAtMost:
        if (static_cast<int>(key.ownerTrust()) > static_cast<int>(d_ptr->mOwnerTrustReferenceLevel)) {
            return false;
        }
        break;
    }
    const UserID uid = key.userID(0);
    switch (d_ptr->mValidity) {
    default:
    case LevelDoesNotMatter:
        break;
    case Is:
        if (uid.validity() != d_ptr->mValidityReferenceLevel) {
            return false;
        }
        break;
    case IsNot:
        if (uid.validity() == d_ptr->mValidityReferenceLevel) {
            return false;
        }
        break;
    case IsAtLeast:
        if (static_cast<int>(uid.validity()) < static_cast<int>(d_ptr->mValidityReferenceLevel)) {
            return false;
        }
        break;
    case IsAtMost:
        if (static_cast<int>(uid.validity()) > static_cast<int>(d_ptr->mValidityReferenceLevel)) {
            return false;
        }
        break;
    }
    return true;
}

KeyFilter::FontDescription DefaultKeyFilter::fontDescription() const
{
    if (d_ptr->mUseFullFont) {
        return FontDescription::create(font(), bold(), italic(), strikeOut());
    } else {
        return FontDescription::create(bold(), italic(), strikeOut());
    }
}

void DefaultKeyFilter::setFgColor(const QColor &value) const
{
    d_ptr->mFgColor = value;
}

void DefaultKeyFilter::setBgColor(const QColor &value) const
{
    d_ptr->mBgColor = value;
}

void DefaultKeyFilter::setName(const QString &value) const
{
    d_ptr->mName = value;
}

void DefaultKeyFilter::setIcon(const QString &value) const
{
    d_ptr->mIcon = value;
}

void DefaultKeyFilter::setId(const QString &value) const
{
    d_ptr->mId = value;
}

void DefaultKeyFilter::setMatchContexts(MatchContexts value) const
{
    d_ptr->mMatchContexts = value;
}

void DefaultKeyFilter::setSpecificity(unsigned int value) const
{
    d_ptr->mSpecificity = value;
}

void DefaultKeyFilter::setItalic(bool value) const
{
    d_ptr->mItalic = value;
}

void DefaultKeyFilter::setBold(bool value) const
{
    d_ptr->mBold = value;
}

void DefaultKeyFilter::setStrikeOut(bool value) const
{
    d_ptr->mStrikeOut = value;
}

void DefaultKeyFilter::setUseFullFont(bool value) const
{
    d_ptr->mUseFullFont = value;
}

void DefaultKeyFilter::setFont(const QFont &value) const
{
    d_ptr->mFont = value;
}

void DefaultKeyFilter::setRevoked(DefaultKeyFilter::TriState value) const
{
    d_ptr->mRevoked = value;
}

void DefaultKeyFilter::setExpired(DefaultKeyFilter::TriState value) const
{
    d_ptr->mExpired = value;
}

void DefaultKeyFilter::setInvalid(DefaultKeyFilter::TriState value) const
{
    d_ptr->mInvalid = value;
}

void DefaultKeyFilter::setDisabled(DefaultKeyFilter::TriState value) const
{
    d_ptr->mDisabled = value;
}

void DefaultKeyFilter::setRoot(DefaultKeyFilter::TriState value) const
{
    d_ptr->mRoot = value;
}

void DefaultKeyFilter::setCanEncrypt(DefaultKeyFilter::TriState value) const
{
    d_ptr->mCanEncrypt = value;
}

void DefaultKeyFilter::setCanSign(DefaultKeyFilter::TriState value) const
{
    d_ptr->mCanSign = value;
}

void DefaultKeyFilter::setCanCertify(DefaultKeyFilter::TriState value) const
{
    d_ptr->mCanCertify = value;
}

void DefaultKeyFilter::setCanAuthenticate(DefaultKeyFilter::TriState value) const
{
    d_ptr->mCanAuthenticate = value;
}

void DefaultKeyFilter::setQualified(DefaultKeyFilter::TriState value) const
{
    d_ptr->mQualified = value;
}

void DefaultKeyFilter::setCardKey(DefaultKeyFilter::TriState value) const
{
    d_ptr->mCardKey = value;
}

void DefaultKeyFilter::setHasSecret(DefaultKeyFilter::TriState value) const
{
    d_ptr->mHasSecret = value;
}

void DefaultKeyFilter::setIsOpenPGP(DefaultKeyFilter::TriState value) const
{
    d_ptr->mIsOpenPGP = value;
}

void DefaultKeyFilter::setWasValidated(DefaultKeyFilter::TriState value) const
{
    d_ptr->mWasValidated = value;
}

void DefaultKeyFilter::setOwnerTrust(DefaultKeyFilter::LevelState value) const
{
    d_ptr->mOwnerTrust = value;
}

void DefaultKeyFilter::setOwnerTrustReferenceLevel(GpgME::Key::OwnerTrust value) const
{
    d_ptr->mOwnerTrustReferenceLevel = value;
}

void DefaultKeyFilter::setValidity(DefaultKeyFilter::LevelState value) const
{
    d_ptr->mValidity = value;
}

void DefaultKeyFilter::setValidityReferenceLevel(GpgME::UserID::Validity value) const
{
    d_ptr->mValidityReferenceLevel = value;
}

void DefaultKeyFilter::setIsDeVs(DefaultKeyFilter::TriState value) const
{
    d_ptr->mIsDeVs = value;
}

void DefaultKeyFilter::setIsBad(DefaultKeyFilter::TriState value) const
{
    d_ptr->mBad = value;
}

QColor DefaultKeyFilter::fgColor() const
{
    return d_ptr->mFgColor;
}

QColor DefaultKeyFilter::bgColor() const
{
    return d_ptr->mBgColor;
}

QString DefaultKeyFilter::name() const
{
    return d_ptr->mName;
}

QString DefaultKeyFilter::icon() const
{
    return d_ptr->mIcon;
}

QString DefaultKeyFilter::id() const
{
    return d_ptr->mId;
}

QFont DefaultKeyFilter::font() const
{
    return d_ptr->mFont;
}

KeyFilter::MatchContexts DefaultKeyFilter::availableMatchContexts() const
{
    return d_ptr->mMatchContexts;
}

unsigned int DefaultKeyFilter::specificity() const
{
    return d_ptr->mSpecificity;
}

bool DefaultKeyFilter::italic() const
{
    return d_ptr->mItalic;
}

bool DefaultKeyFilter::bold() const
{
    return d_ptr->mBold;
}

bool DefaultKeyFilter::strikeOut() const
{
    return d_ptr->mStrikeOut;
}

bool DefaultKeyFilter::useFullFont() const
{
    return d_ptr->mUseFullFont;
}

DefaultKeyFilter::TriState DefaultKeyFilter::revoked() const
{
    return d_ptr->mRevoked;
}

DefaultKeyFilter::TriState DefaultKeyFilter::expired() const
{
    return d_ptr->mExpired;
}

DefaultKeyFilter::TriState DefaultKeyFilter::invalid() const
{
    return d_ptr->mInvalid;
}

DefaultKeyFilter::TriState DefaultKeyFilter::disabled() const
{
    return d_ptr->mDisabled;
}

DefaultKeyFilter::TriState DefaultKeyFilter::root() const
{
    return d_ptr->mRoot;
}

DefaultKeyFilter::TriState DefaultKeyFilter::canEncrypt() const
{
    return d_ptr->mCanEncrypt;
}

DefaultKeyFilter::TriState DefaultKeyFilter::canSign() const
{
    return d_ptr->mCanSign;
}

DefaultKeyFilter::TriState DefaultKeyFilter::canCertify() const
{
    return d_ptr->mCanCertify;
}

DefaultKeyFilter::TriState DefaultKeyFilter::canAuthenticate() const
{
    return d_ptr->mCanAuthenticate;
}

DefaultKeyFilter::TriState DefaultKeyFilter::qualified() const
{
    return d_ptr->mQualified;
}

DefaultKeyFilter::TriState DefaultKeyFilter::cardKey() const
{
    return d_ptr->mCardKey;
}

DefaultKeyFilter::TriState DefaultKeyFilter::hasSecret() const
{
    return d_ptr->mHasSecret;
}

DefaultKeyFilter::TriState DefaultKeyFilter::isOpenPGP() const
{
    return d_ptr->mIsOpenPGP;
}

DefaultKeyFilter::TriState DefaultKeyFilter::wasValidated() const
{
    return d_ptr->mWasValidated;
}

DefaultKeyFilter::LevelState DefaultKeyFilter::ownerTrust() const
{
    return d_ptr->mOwnerTrust;
}

GpgME::Key::OwnerTrust DefaultKeyFilter::ownerTrustReferenceLevel() const
{
    return d_ptr->mOwnerTrustReferenceLevel;
}

DefaultKeyFilter::LevelState DefaultKeyFilter::validity() const
{
    return d_ptr->mValidity;
}

GpgME::UserID::Validity DefaultKeyFilter::validityReferenceLevel() const
{
    return d_ptr->mValidityReferenceLevel;
}

DefaultKeyFilter::TriState DefaultKeyFilter::isDeVS() const
{
    return d_ptr->mIsDeVs;
}

DefaultKeyFilter::TriState DefaultKeyFilter::isBad() const
{
    return d_ptr->mBad;
}
