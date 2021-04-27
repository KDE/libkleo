/*
    kleo/enum.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

class QString;
#include <QStringList>

namespace GpgME {
class Key;
class UserID;
}

namespace Kleo
{

enum class KeyUsage : char {
    AnyUsage,
    Sign,
    Encrypt,
    Certify,
    Authenticate,
};

enum CryptoMessageFormat {
    InlineOpenPGPFormat = 1,
    OpenPGPMIMEFormat = 2,
    SMIMEFormat = 4,
    SMIMEOpaqueFormat = 8,
    AnyOpenPGP = InlineOpenPGPFormat | OpenPGPMIMEFormat,
    AnySMIME = SMIMEOpaqueFormat | SMIMEFormat,
    AutoFormat = AnyOpenPGP | AnySMIME
};

KLEO_EXPORT QString cryptoMessageFormatToLabel(CryptoMessageFormat f);

KLEO_EXPORT const char *cryptoMessageFormatToString(CryptoMessageFormat f);
KLEO_EXPORT QStringList cryptoMessageFormatsToStringList(unsigned int f);
KLEO_EXPORT CryptoMessageFormat stringToCryptoMessageFormat(const QString &s);
KLEO_EXPORT unsigned int stringListToCryptoMessageFormats(const QStringList &sl);

enum Action {
    Conflict, DoIt, DontDoIt, Ask, AskOpportunistic, Impossible
};

enum EncryptionPreference {
    UnknownPreference = 0,
    NeverEncrypt = 1,
    AlwaysEncrypt = 2,
    AlwaysEncryptIfPossible = 3,
    AlwaysAskForEncryption = 4,
    AskWheneverPossible = 5,
    MaxEncryptionPreference = AskWheneverPossible
};

KLEO_EXPORT QString encryptionPreferenceToLabel(EncryptionPreference pref);
KLEO_EXPORT const char *encryptionPreferenceToString(EncryptionPreference pref);
KLEO_EXPORT EncryptionPreference stringToEncryptionPreference(const QString &str);

enum SigningPreference {
    UnknownSigningPreference = 0,
    NeverSign = 1,
    AlwaysSign = 2,
    AlwaysSignIfPossible = 3,
    AlwaysAskForSigning = 4,
    AskSigningWheneverPossible = 5,
    MaxSigningPreference = AskSigningWheneverPossible
};

KLEO_EXPORT QString signingPreferenceToLabel(SigningPreference pref);
KLEO_EXPORT const char *signingPreferenceToString(SigningPreference pref);
KLEO_EXPORT SigningPreference stringToSigningPreference(const QString &str);

enum TrustLevel {
    Level0,
    Level1,
    Level2,
    Level3,
    Level4
};

KLEO_EXPORT TrustLevel trustLevel(const GpgME::Key &key);
KLEO_EXPORT TrustLevel trustLevel(const GpgME::UserID &uid);


}

