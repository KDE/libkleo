/*
    kconfigbasedkeyfilter.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "kconfigbasedkeyfilter.h"

#include <KConfigBase>
#include <KConfigGroup>

#include <algorithm>
#include <QDebug>

using namespace Kleo;
using namespace GpgME;

//
//
// FontDescription - intuitive font property resolving
//                   (QFont::resolve doesn't work for us)
//
//
struct KeyFilter::FontDescription::Private {
    bool bold, italic, strikeOut, fullFont;
    QFont font;
};

KeyFilter::FontDescription::FontDescription()
    : d(new Private)
{
    d->bold = d->italic = d->strikeOut = d->fullFont = false;
}

KeyFilter::FontDescription::FontDescription(const FontDescription &other)
    : d(new Private(*other.d))
{

}

KeyFilter::FontDescription::~FontDescription()
{
    delete d;
}

KeyFilter::FontDescription KeyFilter::FontDescription::create(bool b, bool i, bool s)
{
    FontDescription fd;
    fd.d->bold = b;
    fd.d->italic = i;
    fd.d->strikeOut = s;
    return fd;
}

KeyFilter::FontDescription KeyFilter::FontDescription::create(const QFont &f, bool b, bool i, bool s)
{
    FontDescription fd;
    fd.d->fullFont = true;
    fd.d->font = f;
    fd.d->bold = b;
    fd.d->italic = i;
    fd.d->strikeOut = s;
    return fd;
}

QFont KeyFilter::FontDescription::font(const QFont &base) const
{
    QFont font;
    if (d->fullFont) {
        font = d->font;
        font.setPointSize(base.pointSize());
    } else {
        font = base;
    }
    if (d->bold) {
        font.setBold(true);
    }
    if (d->italic) {
        font.setItalic(true);
    }
    if (d->strikeOut) {
        font.setStrikeOut(true);
    }
    return font;
}

KeyFilter::FontDescription KeyFilter::FontDescription::resolve(const FontDescription &other) const
{
    FontDescription fd;
    fd.d->fullFont = this->d->fullFont || other.d->fullFont;
    if (fd.d->fullFont) {
        fd.d->font = this->d->fullFont ? this->d->font : other.d->font;
    }
    fd.d->bold = this->d->bold || other.d->bold;
    fd.d->italic = this->d->italic || other.d->italic;
    fd.d->strikeOut = this->d->strikeOut || other.d->strikeOut;
    return fd;
}

static const struct {
    const char *name;
    Key::OwnerTrust trust;
    UserID::Validity validity;
} ownerTrustAndValidityMap[] = {
    { "unknown",   Key::Unknown,   UserID::Unknown   },
    { "undefined", Key::Undefined, UserID::Undefined },
    { "never",     Key::Never,     UserID::Never     },
    { "marginal",  Key::Marginal,  UserID::Marginal  },
    { "full",      Key::Full,      UserID::Full      },
    { "ultimate",  Key::Ultimate,  UserID::Ultimate  },
};

static Key::OwnerTrust map2OwnerTrust(const QString &s)
{
    for (unsigned int i = 0; i < sizeof ownerTrustAndValidityMap / sizeof * ownerTrustAndValidityMap; ++i)
        if (s.toLower() == QLatin1String(ownerTrustAndValidityMap[i].name)) {
            return ownerTrustAndValidityMap[i].trust;
        }
    return ownerTrustAndValidityMap[0].trust;
}

static UserID::Validity map2Validity(const QString &s)
{
    for (unsigned int i = 0; i < sizeof ownerTrustAndValidityMap / sizeof * ownerTrustAndValidityMap; ++i)
        if (s.toLower() == QLatin1String(ownerTrustAndValidityMap[i].name)) {
            return ownerTrustAndValidityMap[i].validity;
        }
    return ownerTrustAndValidityMap[0].validity;
}

KConfigBasedKeyFilter::KConfigBasedKeyFilter(const KConfigGroup &config)
    : DefaultKeyFilter()
{
    setFgColor(config.readEntry<QColor>("foreground-color", QColor()));
    setBgColor(config.readEntry<QColor>("background-color", QColor()));
    setName(config.readEntry("Name", config.name()));
    setIcon(config.readEntry("icon"));
    setId(config.readEntry("id", config.name()));
    if (config.hasKey("font")) {
        setUseFullFont(true);
        setFont(config.readEntry("font"));
    } else {
        setUseFullFont(false);
        setItalic(config.readEntry("font-italic", false));
        setBold(config.readEntry("font-bold", false));
    }
    setStrikeOut(config.readEntry("font-strikeout", false));
#ifdef SET
#undef SET
#endif
#define SET(member,key) \
    if ( config.hasKey( key ) ) { \
        set##member(config.readEntry( key, false ) ? Set : NotSet); \
        setSpecificity(specificity() + 1); \
    }
    SET(Revoked, "is-revoked");
    SET(Expired, "is-expired");
    SET(Disabled, "is-disabled");
    SET(Root, "is-root-certificate");
    SET(CanEncrypt, "can-encrypt");
    SET(CanSign, "can-sign");
    SET(CanCertify, "can-certify");
    SET(CanAuthenticate, "can-authenticate");
    SET(Qualified, "is-qualified");
    SET(CardKey, "is-cardkey");
    SET(HasSecret, "has-secret-key");
    SET(IsOpenPGP, "is-openpgp-key");
    SET(WasValidated, "was-validated");
    SET(IsDeVs, "is-de-vs");
#undef SET
    static const struct {
        const char *prefix;
        LevelState state;
    } prefixMap[] = {
        { "is-", Is },
        { "is-not-", IsNot },
        { "is-at-least-", IsAtLeast },
        { "is-at-most-", IsAtMost },
    };
    for (unsigned int i = 0; i < sizeof prefixMap / sizeof * prefixMap; ++i) {
        const QString key = QLatin1String(prefixMap[i].prefix) + QLatin1String("ownertrust");
        if (config.hasKey(key)) {
            setOwnerTrust(prefixMap[i].state);
            setOwnerTrustReferenceLevel(map2OwnerTrust(config.readEntry(key, QString())));
            setSpecificity(specificity() + 1);
            break;
        }
    }
    for (unsigned int i = 0; i < sizeof prefixMap / sizeof * prefixMap; ++i) {
        const QString key = QLatin1String(prefixMap[i].prefix) + QLatin1String("validity");
        if (config.hasKey(key)) {
            setValidity(prefixMap[i].state);
            setValidityReferenceLevel(map2Validity(config.readEntry(key, QString())));
            setSpecificity(specificity() + 1);
            break;
        }
    }
    static const struct {
        const char *key;
        MatchContext context;
    } matchMap[] = {
        { "any", AnyMatchContext },
        { "appearance", Appearance },
        { "filtering", Filtering },
    };
    const QStringList contexts = config.readEntry("match-contexts", "any").toLower().split(QRegExp(QLatin1String("[^a-zA-Z0-9_-!]+")), Qt::SkipEmptyParts);
    setMatchContexts(NoMatchContext);
    for (const QString & ctx : contexts) {
        bool found = false;
        for (unsigned int i = 0; i < sizeof matchMap / sizeof * matchMap; ++i)
            if (ctx == QLatin1String(matchMap[i].key)) {
                setMatchContexts(availableMatchContexts() |= matchMap[i].context);
                found = true;
                break;
            } else if (ctx.startsWith(QLatin1Char('!')) && ctx.mid(1) == QLatin1String(matchMap[i].key)) {
                setMatchContexts(availableMatchContexts() &= matchMap[i].context);
                found = true;
                break;
            }
        if (!found) {
            qWarning() << QStringLiteral("KConfigBasedKeyFilter: found unknown match context '%1' in group '%2'").arg(ctx, config.name());
        }
    }
    if (availableMatchContexts() == NoMatchContext) {
        qWarning() << QStringLiteral("KConfigBasedKeyFilter: match context in group '%1' evaluates to NoMatchContext, "
                                     "replaced by AnyMatchContext").arg(config.name());
        setMatchContexts(AnyMatchContext);
    }
}
