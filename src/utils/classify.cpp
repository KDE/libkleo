/* -*- mode: c++; c-basic-offset:4 -*-
    utils/classify.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "classify.h"

#include "algorithm.h"

#include <libkleo/checksumdefinition.h>

#include <libkleo_debug.h>

#include <QGpgME/DataProvider>

#include <QByteArrayMatcher>
#include <QFile>
#include <QFileInfo>
#include <QMap>
#include <QRegExp>
#include <QRegularExpression>
#include <QString>

#include <gpgme++/data.h>

#include <functional>
#include <iterator>

using namespace Kleo::Class;

namespace
{

const unsigned int ExamineContentHint = 0x8000;

static const struct _classification {
    char extension[4];
    unsigned int classification;
} classifications[] = {
    // ordered by extension
    {"arl", Kleo::Class::CMS | Binary | CertificateRevocationList},
    {"asc", Kleo::Class::OpenPGP | Ascii | OpaqueSignature | DetachedSignature | CipherText | AnyCertStoreType | ExamineContentHint},
    {"cer", Kleo::Class::CMS | Binary | Certificate},
    {"crl", Kleo::Class::CMS | Binary | CertificateRevocationList},
    {"crt", Kleo::Class::CMS | Binary | Certificate},
    {"der", Kleo::Class::CMS | Binary | Certificate | CertificateRevocationList},
    {"gpg", Kleo::Class::OpenPGP | Binary | OpaqueSignature | CipherText | AnyCertStoreType | ExamineContentHint},
    {"p10", Kleo::Class::CMS | Ascii | CertificateRequest},
    {"p12", Kleo::Class::CMS | Binary | ExportedPSM},
    {"p7c", Kleo::Class::CMS | Binary | Certificate},
    {"p7m", Kleo::Class::CMS | AnyFormat | CipherText},
    {"p7s", Kleo::Class::CMS | AnyFormat | AnySignature},
    {"pem", Kleo::Class::CMS | Ascii | AnyType | ExamineContentHint},
    {"pfx", Kleo::Class::CMS | Binary | Certificate},
    {"pgp", Kleo::Class::OpenPGP | Binary | OpaqueSignature | CipherText | AnyCertStoreType | ExamineContentHint},
    {"sig", Kleo::Class::OpenPGP | AnyFormat | DetachedSignature},
};

static const QMap<GpgME::Data::Type, unsigned int> gpgmeTypeMap{
    // clang-format off
    {GpgME::Data::PGPSigned,    Kleo::Class::OpenPGP | OpaqueSignature  },
    /* PGPOther might be just an unencrypted unsigned pgp message. Decrypt
     * would yield the plaintext anyway so for us this is CipherText. */
    {GpgME::Data::PGPOther,     Kleo::Class::OpenPGP | CipherText       },
    {GpgME::Data::PGPKey,       Kleo::Class::OpenPGP | Certificate      },
    {GpgME::Data::CMSSigned,    Kleo::Class::CMS | AnySignature         },
    {GpgME::Data::CMSEncrypted, Kleo::Class::CMS | CipherText           },
    /* See PGPOther */
    {GpgME::Data::CMSOther,     Kleo::Class::CMS | CipherText           },
    {GpgME::Data::X509Cert,     Kleo::Class::CMS | Certificate          },
    {GpgME::Data::PKCS12,       Kleo::Class::CMS | Binary | ExportedPSM },
    {GpgME::Data::PGPEncrypted, Kleo::Class::OpenPGP | CipherText       },
    {GpgME::Data::PGPSignature, Kleo::Class::OpenPGP | DetachedSignature},
    // clang-format on
};

static const unsigned int defaultClassification = NoClass;

template<template<typename U> class Op>
struct ByExtension {
    using result_type = bool;

    template<typename T>
    bool operator()(const T &lhs, const T &rhs) const
    {
        return Op<int>()(qstricmp(lhs.extension, rhs.extension), 0);
    }
    template<typename T>
    bool operator()(const T &lhs, const char *rhs) const
    {
        return Op<int>()(qstricmp(lhs.extension, rhs), 0);
    }
    template<typename T>
    bool operator()(const char *lhs, const T &rhs) const
    {
        return Op<int>()(qstricmp(lhs, rhs.extension), 0);
    }
    bool operator()(const char *lhs, const char *rhs) const
    {
        return Op<int>()(qstricmp(lhs, rhs), 0);
    }
};

static const struct _content_classification {
    char content[28];
    unsigned int classification;
} content_classifications[] = {
    // clang-format off
    {"CERTIFICATE",       Certificate                           },
    {"ENCRYPTED MESSAGE", CipherText                            },
    {"MESSAGE",           OpaqueSignature | CipherText          },
    {"PKCS12",            ExportedPSM                           },
    {"PRIVATE KEY BLOCK", ExportedPSM                           },
    {"PUBLIC KEY BLOCK",  Certificate                           },
    {"SIGNATURE",         DetachedSignature                     },
    {"SIGNED MESSAGE",    ClearsignedMessage | DetachedSignature},
    // clang-format on
};

template<template<typename U> class Op>
struct ByContent {
    using result_type = bool;

    const unsigned int N;
    explicit ByContent(unsigned int n)
        : N(n)
    {
    }

    template<typename T>
    bool operator()(const T &lhs, const T &rhs) const
    {
        return Op<int>()(qstrncmp(lhs.content, rhs.content, N), 0);
    }
    template<typename T>
    bool operator()(const T &lhs, const char *rhs) const
    {
        return Op<int>()(qstrncmp(lhs.content, rhs, N), 0);
    }
    template<typename T>
    bool operator()(const char *lhs, const T &rhs) const
    {
        return Op<int>()(qstrncmp(lhs, rhs.content, N), 0);
    }
    bool operator()(const char *lhs, const char *rhs) const
    {
        return Op<int>()(qstrncmp(lhs, rhs, N), 0);
    }
};

}

unsigned int Kleo::classify(const QStringList &fileNames)
{
    if (fileNames.empty()) {
        return 0;
    }
    unsigned int result = classify(fileNames.front());
    for (const QString &fileName : fileNames) {
        result &= classify(fileName);
    }
    return result;
}

static unsigned int classifyExtension(const QFileInfo &fi)
{
    const _classification *const it =
        Kleo::binary_find(std::begin(classifications), std::end(classifications), fi.suffix().toLatin1().constData(), ByExtension<std::less>());
    if (it != std::end(classifications)) {
        if (!(it->classification & ExamineContentHint)) {
            return it->classification;
        }
    }

    return it == std::end(classifications) ? defaultClassification : it->classification;
}

unsigned int Kleo::classify(const QString &filename)
{
    Q_ASSERT(std::is_sorted(std::begin(classifications), std::end(classifications), ByExtension<std::less>()));

    const QFileInfo fi(filename);

    if (!fi.exists()) {
        return 0;
    }

    QFile file(filename);
    /* The least reliable but always available classification */
    const unsigned int extClass = classifyExtension(fi);
    if (!file.open(QIODevice::ReadOnly)) {
        qCDebug(LIBKLEO_LOG) << "Failed to open file: " << filename << " for classification.";
        return extClass;
    }

    /* More reliable */
    const unsigned int contentClass = classifyContent(file.read(4096));
    if (contentClass != defaultClassification) {
        qCDebug(LIBKLEO_LOG) << "Classified based on content as:" << contentClass;
        return contentClass;
    }

    /* Probably some X509 Stuff that GpgME in its wisdom does not handle. Again
     * file extension is probably more reliable as the last resort. */
    qCDebug(LIBKLEO_LOG) << "No classification based on content.";
    return extClass;
}

unsigned int Kleo::classifyContent(const QByteArray &data)
{
    QGpgME::QByteArrayDataProvider dp(data);
    GpgME::Data gpgmeData(&dp);
    GpgME::Data::Type type = gpgmeData.type();

    return gpgmeTypeMap.value(type, defaultClassification);
}

QString Kleo::printableClassification(unsigned int classification)
{
    QStringList parts;
    if (classification & Kleo::Class::CMS) {
        parts.push_back(QStringLiteral("CMS"));
    }
    if (classification & Kleo::Class::OpenPGP) {
        parts.push_back(QStringLiteral("OpenPGP"));
    }
    if (classification & Kleo::Class::Binary) {
        parts.push_back(QStringLiteral("Binary"));
    }
    if (classification & Kleo::Class::Ascii) {
        parts.push_back(QStringLiteral("Ascii"));
    }
    if (classification & Kleo::Class::DetachedSignature) {
        parts.push_back(QStringLiteral("DetachedSignature"));
    }
    if (classification & Kleo::Class::OpaqueSignature) {
        parts.push_back(QStringLiteral("OpaqueSignature"));
    }
    if (classification & Kleo::Class::ClearsignedMessage) {
        parts.push_back(QStringLiteral("ClearsignedMessage"));
    }
    if (classification & Kleo::Class::CipherText) {
        parts.push_back(QStringLiteral("CipherText"));
    }
    if (classification & Kleo::Class::Certificate) {
        parts.push_back(QStringLiteral("Certificate"));
    }
    if (classification & Kleo::Class::ExportedPSM) {
        parts.push_back(QStringLiteral("ExportedPSM"));
    }
    if (classification & Kleo::Class::CertificateRequest) {
        parts.push_back(QStringLiteral("CertificateRequest"));
    }
    return parts.join(QLatin1String(", "));
}

/*!
  \return the data file that corresponds to the signature file \a
  signatureFileName, or QString(), if no such file can be found.
*/
QString Kleo::findSignedData(const QString &signatureFileName)
{
    if (!mayBeDetachedSignature(signatureFileName)) {
        return QString();
    }

    const QFileInfo fi{signatureFileName};
    const QString baseName = signatureFileName.chopped(fi.suffix().size() + 1);
    return QFile::exists(baseName) ? baseName : QString();
}

/*!
  \return all (existing) candidate signature files for \a signedDataFileName

  Note that there can very well be more than one such file, e.g. if
  the same data file was signed by both CMS and OpenPGP certificates.
*/
QStringList Kleo::findSignatures(const QString &signedDataFileName)
{
    QStringList result;
    for (unsigned int i = 0, end = sizeof(classifications) / sizeof(_classification); i < end; ++i) {
        if (classifications[i].classification & DetachedSignature) {
            const QString candidate = signedDataFileName + QLatin1Char('.') + QLatin1String(classifications[i].extension);
            if (QFile::exists(candidate)) {
                result.push_back(candidate);
            }
        }
    }
    return result;
}

/*!
  \return the (likely) output filename for \a inputFileName, or
  "inputFileName.out" if none can be determined.
*/
QString Kleo::outputFileName(const QString &inputFileName)
{
    const QFileInfo fi(inputFileName);
    const QString suffix = fi.suffix();

    if (!std::binary_search(std::begin(classifications), std::end(classifications), suffix.toLatin1().constData(), ByExtension<std::less>())) {
        return inputFileName + QLatin1String(".out");
    } else {
        return inputFileName.chopped(suffix.size() + 1);
    }
}

/*!
  \return the commonly used extension for files of type
  \a classification, or NULL if none such exists.
*/
const char *Kleo::outputFileExtension(unsigned int classification, bool usePGPFileExt)
{
    if (usePGPFileExt && (classification & Class::OpenPGP) && (classification & Class::Binary)) {
        return "pgp";
    }

    for (unsigned int i = 0; i < sizeof classifications / sizeof *classifications; ++i) {
        if ((classifications[i].classification & classification) == classification) {
            return classifications[i].extension;
        }
    }
    return nullptr;
}

bool Kleo::isFingerprint(const QString &fpr)
{
    static QRegularExpression fprRegex(QStringLiteral("[0-9a-fA-F]{40}"));
    return fprRegex.match(fpr).hasMatch();
}

bool Kleo::isChecksumFile(const QString &file)
{
    static bool initialized;
    static QList<QRegExp> patterns;
    const QFileInfo fi(file);
    if (!fi.exists()) {
        return false;
    }
    if (!initialized) {
        const auto getChecksumDefinitions = ChecksumDefinition::getChecksumDefinitions();
        for (const std::shared_ptr<ChecksumDefinition> &cd : getChecksumDefinitions) {
            if (cd) {
                const auto patternsList = cd->patterns();
                for (const QString &pattern : patternsList) {
#ifdef Q_OS_WIN
                    patterns << QRegExp(pattern, Qt::CaseInsensitive);
#else
                    patterns << QRegExp(pattern, Qt::CaseSensitive);
#endif
                }
            }
        }
        initialized = true;
    }

    const QString fileName = fi.fileName();
    for (const QRegExp &pattern : std::as_const(patterns)) {
        if (pattern.exactMatch(fileName)) {
            return true;
        }
    }
    return false;
}
