/* -*- mode: c++; c-basic-offset:4 -*-
    utils/classify.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <gpgme++/global.h>

class QByteArray;
class QString;
class QStringList;

namespace Kleo
{

namespace Class
{
enum {
    NoClass = 0,

    // protocol:
    CMS          = 0x01,
    OpenPGP      = 0x02,

    AnyProtocol  = OpenPGP | CMS,
    ProtocolMask = AnyProtocol,

    // format:
    Binary     = 0x04,
    Ascii      = 0x08,

    AnyFormat  = Binary | Ascii,
    FormatMask = AnyFormat,

    // type:
    DetachedSignature  = 0x010,
    OpaqueSignature    = 0x020,
    ClearsignedMessage = 0x040,

    AnySignature       = DetachedSignature | OpaqueSignature | ClearsignedMessage,

    CipherText         = 0x080,

    AnyMessageType     = AnySignature | CipherText,

    Importable         = 0x100,
    Certificate        = 0x200 | Importable,
    ExportedPSM        = 0x400 | Importable,

    AnyCertStoreType   = Certificate | ExportedPSM,

    CertificateRequest = 0x800,

    CertificateRevocationList = 0x1000,

    AnyType            = AnyMessageType | AnyCertStoreType | CertificateRequest | CertificateRevocationList,
    TypeMask           = AnyType
};
}

KLEO_EXPORT unsigned int classify(const QString &filename);
KLEO_EXPORT unsigned int classify(const QStringList &fileNames);
KLEO_EXPORT unsigned int classifyContent(const QByteArray &data);

KLEO_EXPORT QString findSignedData(const QString &signatureFileName);
KLEO_EXPORT QStringList findSignatures(const QString &signedDataFileName);
KLEO_EXPORT QString outputFileName(const QString &input);

/** Check if a string looks like a fingerprint (SHA1 sum) */
KLEO_EXPORT bool isFingerprint(const QString &fpr);

/** Check if a filename matches a ChecksumDefinition pattern */
KLEO_EXPORT bool isChecksumFile(const QString &file);

KLEO_EXPORT const char *outputFileExtension(unsigned int classification, bool usePGPFileExt);

KLEO_EXPORT QString printableClassification(unsigned int classification);

inline bool isCMS(const QString &filename)
{
    return (classify(filename) & Class::ProtocolMask) == Class::CMS;
}
inline bool isCMS(const unsigned int classification)
{
    return (classification & Class::ProtocolMask) == Class::CMS;
}
inline bool mayBeCMS(const QString &filename)
{
    return classify(filename) & Class::CMS;
}
inline bool mayBeCMS(const unsigned int classification)
{
    return classification & Class::CMS;
}

inline bool isOpenPGP(const QString &filename)
{
    return (classify(filename) & Class::ProtocolMask) == Class::OpenPGP;
}
inline bool isOpenPGP(const unsigned int classification)
{
    return (classification & Class::ProtocolMask) == Class::OpenPGP;
}
inline bool mayBeOpenPGP(const QString &filename)
{
    return classify(filename) & Class::OpenPGP;
}
inline bool mayBeOpenPGP(const unsigned int classification)
{
    return classification & Class::OpenPGP;
}

inline bool isBinary(const QString &filename)
{
    return (classify(filename) & Class::FormatMask) == Class::Binary;
}
inline bool isBinary(const unsigned int classification)
{
    return (classification & Class::FormatMask) == Class::Binary;
}
inline bool mayBeBinary(const QString &filename)
{
    return classify(filename) & Class::Binary;
}
inline bool mayBeBinary(const unsigned int classification)
{
    return classification & Class::Binary;
}

inline bool isAscii(const QString &filename)
{
    return (classify(filename) & Class::FormatMask) == Class::Ascii;
}
inline bool isAscii(const unsigned int classification)
{
    return (classification & Class::FormatMask) == Class::Ascii;
}
inline bool mayBeAscii(const QString &filename)
{
    return classify(filename) & Class::Ascii;
}
inline bool mayBeAscii(const unsigned int classification)
{
    return classification & Class::Ascii;
}

inline bool isDetachedSignature(const QString &filename)
{
    return (classify(filename) & Class::TypeMask) == Class::DetachedSignature;
}
inline bool isDetachedSignature(const unsigned int classification)
{
    return (classification & Class::TypeMask) == Class::DetachedSignature;
}
inline bool mayBeDetachedSignature(const QString &filename)
{
    return classify(filename) & Class::DetachedSignature;
}
inline bool mayBeDetachedSignature(const unsigned int classification)
{
    return classification & Class::DetachedSignature;
}

inline bool isOpaqueSignature(const QString &filename)
{
    return (classify(filename) & Class::TypeMask) == Class::OpaqueSignature;
}
inline bool isOpaqueSignature(const unsigned int classification)
{
    return (classification & Class::TypeMask) == Class::OpaqueSignature;
}
inline bool mayBeOpaqueSignature(const QString &filename)
{
    return classify(filename) & Class::OpaqueSignature;
}
inline bool mayBeOpaqueSignature(const unsigned int classification)
{
    return classification & Class::OpaqueSignature;
}

inline bool isCipherText(const QString &filename)
{
    return (classify(filename) & Class::TypeMask) == Class::CipherText;
}
inline bool isCipherText(const unsigned int classification)
{
    return (classification & Class::TypeMask) == Class::CipherText;
}
inline bool mayBeCipherText(const QString &filename)
{
    return classify(filename) & Class::CipherText;
}
inline bool mayBeCipherText(const unsigned int classification)
{
    return classification & Class::CipherText;
}

inline bool isAnyMessageType(const QString &filename)
{
    return (classify(filename) & Class::TypeMask) == Class::AnyMessageType;
}
inline bool isAnyMessageType(const unsigned int classification)
{
    return (classification & Class::TypeMask) == Class::AnyMessageType;
}
inline bool mayBeAnyMessageType(const QString &filename)
{
    return classify(filename) & Class::AnyMessageType;
}
inline bool mayBeAnyMessageType(const unsigned int classification)
{
    return classification & Class::AnyMessageType;
}

inline bool isCertificateRevocationList(const QString &filename)
{
    return (classify(filename) & Class::TypeMask) == Class::CertificateRevocationList;
}
inline bool isCertificateRevocationList(const unsigned int classification)
{
    return (classification & Class::TypeMask) == Class::CertificateRevocationList;
}
inline bool mayBeCertificateRevocationList(const QString &filename)
{
    return classify(filename) & Class::CertificateRevocationList;
}
inline bool mayBeCertificateRevocationList(const unsigned int classification)
{
    return classification & Class::CertificateRevocationList;
}

inline bool isAnyCertStoreType(const QString &filename)
{
    return (classify(filename) & Class::TypeMask) == Class::AnyCertStoreType;
}
inline bool isAnyCertStoreType(const unsigned int classification)
{
    return (classification & Class::TypeMask) == Class::AnyCertStoreType;
}
inline bool mayBeAnyCertStoreType(const QString &filename)
{
    return classify(filename) & Class::AnyCertStoreType;
}
inline bool mayBeAnyCertStoreType(const unsigned int classification)
{
    return classification & Class::AnyCertStoreType;
}

inline GpgME::Protocol findProtocol(const unsigned int classification)
{
    if (isOpenPGP(classification)) {
        return GpgME::OpenPGP;
    } else if (isCMS(classification)) {
        return GpgME::CMS;
    } else {
        return GpgME::UnknownProtocol;
    }
}
inline GpgME::Protocol findProtocol(const QString &filename)
{
    return findProtocol(classify(filename));
}

}

