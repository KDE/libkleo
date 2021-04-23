/* -*- mode: c++; c-basic-offset:4 -*-
    utils/classify.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <kleo_export.h>

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

#define make_convenience( What, Mask )                                  \
    inline bool is##What( const QString & filename ) {                  \
        return ( classify( filename ) & Class::Mask ) == Class::What ;  \
    }                                                                   \
    inline bool is##What( const unsigned int classification ) {         \
        return ( classification & Class::Mask ) == Class::What ;        \
    }                                                                   \
    inline bool mayBe##What( const QString & filename ) {               \
        return classify( filename ) & Class::What ;                     \
    }                                                                   \
    inline bool mayBe##What( const unsigned int classification ) {      \
        return classification & Class::What ;                           \
    }

make_convenience(CMS,     ProtocolMask)
make_convenience(OpenPGP, ProtocolMask)

make_convenience(Binary, FormatMask)
make_convenience(Ascii,  FormatMask)

make_convenience(DetachedSignature, TypeMask)
make_convenience(OpaqueSignature,   TypeMask)
make_convenience(CipherText,        TypeMask)
make_convenience(AnyMessageType,    TypeMask)
make_convenience(CertificateRevocationList, TypeMask)
make_convenience(AnyCertStoreType,  TypeMask)
#undef make_convenience

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

