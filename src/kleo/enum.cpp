/*
    kleo/enum.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "enum.h"
#include "libkleo_debug.h"
#include "models/keycache.h"

#include <functional>

#include <KLocalizedString>

#include <gpgme++/key.h>
#include <gpgme++/tofuinfo.h>

#include <QString>
#include <QEventLoop>

static const struct {
    Kleo::CryptoMessageFormat format;
    const char *displayName;
    const char *configName;
} cryptoMessageFormats[] = {
    {
        Kleo::InlineOpenPGPFormat,
        I18N_NOOP("Inline OpenPGP (deprecated)"),
        "inline openpgp"
    },
    {
        Kleo::OpenPGPMIMEFormat,
        I18N_NOOP("OpenPGP/MIME"),
        "openpgp/mime"
    },
    {
        Kleo::SMIMEFormat,
        I18N_NOOP("S/MIME"),
        "s/mime"
    },
    {
        Kleo::SMIMEOpaqueFormat,
        I18N_NOOP("S/MIME Opaque"),
        "s/mime opaque"
    },
    {
        Kleo::AnySMIME,
        I18N_NOOP("Any S/MIME"),
        "any s/mime"
    },
    {
        Kleo::AnyOpenPGP,
        I18N_NOOP("Any OpenPGP"),
        "any openpgp"
    },
};
static const unsigned int numCryptoMessageFormats
    = sizeof cryptoMessageFormats / sizeof * cryptoMessageFormats;

const char *Kleo::cryptoMessageFormatToString(Kleo::CryptoMessageFormat f)
{
    if (f == AutoFormat) {
        return "auto";
    }
    for (unsigned int i = 0; i < numCryptoMessageFormats; ++i)
        if (f == cryptoMessageFormats[i].format) {
            return cryptoMessageFormats[i].configName;
        }
    return nullptr;
}

QStringList Kleo::cryptoMessageFormatsToStringList(unsigned int f)
{
    QStringList result;
    for (unsigned int i = 0; i < numCryptoMessageFormats; ++i)
        if (f & cryptoMessageFormats[i].format) {
            result.push_back(QLatin1String(cryptoMessageFormats[i].configName));
        }
    return result;
}

QString Kleo::cryptoMessageFormatToLabel(Kleo::CryptoMessageFormat f)
{
    if (f == AutoFormat) {
        return i18n("Any");
    }
    for (unsigned int i = 0; i < numCryptoMessageFormats; ++i)
        if (f == cryptoMessageFormats[i].format) {
            return i18n(cryptoMessageFormats[i].displayName);
        }
    return QString();
}

Kleo::CryptoMessageFormat Kleo::stringToCryptoMessageFormat(const QString &s)
{
    const QString t = s.toLower();
    for (unsigned int i = 0; i < numCryptoMessageFormats; ++i)
        if (t == QLatin1String(cryptoMessageFormats[i].configName)) {
            return cryptoMessageFormats[i].format;
        }
    return AutoFormat;
}

unsigned int Kleo::stringListToCryptoMessageFormats(const QStringList &sl)
{
    unsigned int result = 0;
    for (QStringList::const_iterator it = sl.begin(); it != sl.end(); ++it) {
        result |= stringToCryptoMessageFormat(*it);
    }
    return result;
}

// For the config values used below, see also kaddressbook/editors/cryptowidget.cpp

const char *Kleo::encryptionPreferenceToString(EncryptionPreference pref)
{
    switch (pref) {
    case UnknownPreference:
        return nullptr;
    case NeverEncrypt:
        return "never";
    case AlwaysEncrypt:
        return "always";
    case AlwaysEncryptIfPossible:
        return "alwaysIfPossible";
    case AlwaysAskForEncryption:
        return "askAlways";
    case AskWheneverPossible:
        return "askWhenPossible";
    }
    return nullptr; // keep the compiler happy
}

Kleo::EncryptionPreference Kleo::stringToEncryptionPreference(const QString &str)
{
    if (str == QLatin1String("never")) {
        return NeverEncrypt;
    }
    if (str == QLatin1String("always")) {
        return AlwaysEncrypt;
    }
    if (str == QLatin1String("alwaysIfPossible")) {
        return AlwaysEncryptIfPossible;
    }
    if (str == QLatin1String("askAlways")) {
        return AlwaysAskForEncryption;
    }
    if (str == QLatin1String("askWhenPossible")) {
        return AskWheneverPossible;
    }
    return UnknownPreference;
}

QString Kleo::encryptionPreferenceToLabel(EncryptionPreference pref)
{
    switch (pref) {
    case NeverEncrypt:
        return i18n("Never Encrypt");
    case AlwaysEncrypt:
        return i18n("Always Encrypt");
    case AlwaysEncryptIfPossible:
        return i18n("Always Encrypt If Possible");
    case AlwaysAskForEncryption:
        return i18n("Ask");
    case AskWheneverPossible:
        return i18n("Ask Whenever Possible");
    default:
        return xi18nc("no specific preference", "<placeholder>none</placeholder>");
    }
}

const char *Kleo::signingPreferenceToString(SigningPreference pref)
{
    switch (pref) {
    case UnknownSigningPreference:
        return nullptr;
    case NeverSign:
        return "never";
    case AlwaysSign:
        return "always";
    case AlwaysSignIfPossible:
        return "alwaysIfPossible";
    case AlwaysAskForSigning:
        return "askAlways";
    case AskSigningWheneverPossible:
        return "askWhenPossible";
    }
    return nullptr; // keep the compiler happy
}

Kleo::SigningPreference Kleo::stringToSigningPreference(const QString &str)
{
    if (str == QLatin1String("never")) {
        return NeverSign;
    }
    if (str == QLatin1String("always")) {
        return AlwaysSign;
    }
    if (str == QLatin1String("alwaysIfPossible")) {
        return AlwaysSignIfPossible;
    }
    if (str == QLatin1String("askAlways")) {
        return AlwaysAskForSigning;
    }
    if (str == QLatin1String("askWhenPossible")) {
        return AskSigningWheneverPossible;
    }
    return UnknownSigningPreference;
}

QString Kleo::signingPreferenceToLabel(SigningPreference pref)
{
    switch (pref) {
    case NeverSign:
        return i18n("Never Sign");
    case AlwaysSign:
        return i18n("Always Sign");
    case AlwaysSignIfPossible:
        return i18n("Always Sign If Possible");
    case AlwaysAskForSigning:
        return i18n("Ask");
    case AskSigningWheneverPossible:
        return i18n("Ask Whenever Possible");
    default:
        return i18nc("no specific preference", "<none>");
    }
}

Kleo::TrustLevel Kleo::trustLevel(const GpgME::Key &key)
{
    TrustLevel maxTl = Level0;
    for (int i = 0, c = key.numUserIDs(); i < c; ++i) {
        const auto tl = trustLevel(key.userID(i));
        maxTl = qMax(maxTl, tl);
        if (maxTl == Level4) {
            break;
        }
    }

    return maxTl;
}

namespace {

bool hasTrustedSignature(const GpgME::UserID &uid)
{
    // lazily intialized cache
    static std::shared_ptr<const Kleo::KeyCache> keyCache;
    if (!keyCache) {
        keyCache = Kleo::KeyCache::instance();
    }
    if (!keyCache->initialized()) {
        QEventLoop el;
        QObject::connect(keyCache.get(), &Kleo::KeyCache::keyListingDone,
                         &el, &QEventLoop::quit);
        el.exec();
    }

    const auto signatures = uid.signatures();
    std::vector<std::string> sigKeyIDs;
    std::transform(signatures.cbegin(), signatures.cend(),
                   std::back_inserter(sigKeyIDs),
                   std::bind(&GpgME::UserID::Signature::signerKeyID, std::placeholders::_1));

    const auto keys = keyCache->findByKeyIDOrFingerprint(sigKeyIDs);
    return std::any_of(keys.cbegin(), keys.cend(),
                       [](const GpgME::Key &key) {
                           return key.ownerTrust() == GpgME::Key::Ultimate;
                       });
}

}

Kleo::TrustLevel Kleo::trustLevel(const GpgME::UserID &uid)
{
    // Modelled after https://wiki.gnupg.org/EasyGpg2016/AutomatedEncryption,
    // but modified to cover all cases, unlike the pseudocode in the document.
    //
    // TODO: Check whether the key comes from a trusted source (Cert/PKA/DANE/WKD)

    switch (uid.validity()) {
    case GpgME::UserID::Unknown:
    case GpgME::UserID::Undefined:
    case GpgME::UserID::Never:
        // Not enough trust -> level 0
        return Level0;

    case GpgME::UserID::Marginal:
        // Marginal trust without TOFU data means the key is still trusted
        // through the Web of Trust -> level 2
        if (uid.tofuInfo().isNull()) {
            return Level2;
        }
        // Marginal trust with TOFU, level will depend on TOFU history
        switch (uid.tofuInfo().validity()) {
        case GpgME::TofuInfo::ValidityUnknown:
        case GpgME::TofuInfo::Conflict:
        case GpgME::TofuInfo::NoHistory:
            // Marginal trust, but not enough history -> level 0
            return Level0;
        case GpgME::TofuInfo::LittleHistory:
            // Marginal trust, but too little history -> level 1
            return Level1;
        case GpgME::TofuInfo::BasicHistory:
        case GpgME::TofuInfo::LargeHistory:
            // Marginal trust and enough history -> level 2
            return Level2;
        }
        return Level2; // Not reached, but avoids fallthrough warnings
    case GpgME::UserID::Full:
        // Full trust, trust level depends whether the UserID is signed with
        // at least one key with Ultimate ownertrust.
        return hasTrustedSignature(uid) ? Level4 : Level3;

    case GpgME::UserID::Ultimate:
        // Ultimate trust -> leve 4
        return Level4;
    }

    Q_UNREACHABLE();
}
