/*
    defaultkeyfilter.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    Copyright (c) 2004 Klarälvdalens Datakonsult AB
    2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH

    Libkleopatra is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    Libkleopatra is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    In addition, as a special exception, the copyright holders give
    permission to link the code of this program with any edition of
    the Qt library by Trolltech AS, Norway (or with modified versions
    of Qt that use the same license as Qt), and distribute linked
    combinations including the two.  You must obey the GNU General
    Public License in all respects for all of the code used other than
    Qt.  If you modify this file, you may extend this exception to
    your version of the file, but you are not obligated to do so.  If
    you do not wish to do so, delete this exception statement from
    your version.
*/

#include "defaultkeyfilter.h"

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
        mSpecificity(0),
        mItalic(false),
        mBold(false),
        mStrikeOut(false),
        mUseFullFont(false),
        mRevoked(DoesNotMatter),
        mExpired(DoesNotMatter),
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
    unsigned int mSpecificity;
    bool mItalic;
    bool mBold;
    bool mStrikeOut;
    bool mUseFullFont;
    QFont mFont;

    TriState mRevoked;
    TriState mExpired;
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
        if ((int)key.ownerTrust() < (int)d_ptr->mOwnerTrustReferenceLevel) {
            return false;
        }
        break;
    case IsAtMost:
        if ((int)key.ownerTrust() > (int)d_ptr->mOwnerTrustReferenceLevel) {
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
        if ((int)uid.validity() < (int)d_ptr->mValidityReferenceLevel) {
            return false;
        }
        break;
    case IsAtMost:
        if ((int)uid.validity() > (int)d_ptr->mValidityReferenceLevel) {
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
