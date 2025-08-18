/* -*- mode: c++; c-basic-offset:4 -*-
    utils/classify.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "classify.h"

#include "algorithm.h"
#include "classifyconfig.h"

#include <libkleo/checksumdefinition.h>

#include <libkleo_debug.h>

#include <QGpgME/DataProvider>

#include <QByteArrayMatcher>
#include <QFile>
#include <QFileInfo>
#include <QMap>
#include <QMimeDatabase>
#include <QRegularExpression>
#include <QString>

#include <gpgme++/data.h>

#include <functional>
#include <iterator>

using namespace Kleo::Class;
using namespace Qt::Literals::StringLiterals;

namespace
{

const unsigned int ExamineContentHint = 0x8000;

static const QMap<QString, unsigned int> classifications{
    // using QMap to keep ordering by extension which incidentally is also the prioritized order for outputFileExtension()
    {QStringLiteral("arl"), Kleo::Class::CMS | Binary | CertificateRevocationList},
    {QStringLiteral("asc"), Kleo::Class::OpenPGP | Ascii | OpaqueSignature | DetachedSignature | CipherText | AnyCertStoreType | ExamineContentHint},
    {QStringLiteral("cer"), Kleo::Class::CMS | Binary | Certificate},
    {QStringLiteral("crl"), Kleo::Class::CMS | Binary | CertificateRevocationList},
    {QStringLiteral("crt"), Kleo::Class::CMS | Binary | Certificate},
    {QStringLiteral("der"), Kleo::Class::CMS | Binary | Certificate | CertificateRevocationList},
    {QStringLiteral("eml"), Kleo::Class::MimeFile | Ascii},
    {QStringLiteral("gpg"), Kleo::Class::OpenPGP | Binary | OpaqueSignature | CipherText | AnyCertStoreType | ExamineContentHint},
    {QStringLiteral("mim"), Kleo::Class::MimeFile | Ascii},
    {QStringLiteral("mime"), Kleo::Class::MimeFile | Ascii},
    {QStringLiteral("mbox"), Kleo::Class::MimeFile | Ascii},
    {QStringLiteral("p10"), Kleo::Class::CMS | Ascii | CertificateRequest},
    {QStringLiteral("p12"), Kleo::Class::CMS | Binary | ExportedPSM},
    {QStringLiteral("p7c"), Kleo::Class::CMS | Binary | Certificate},
    {QStringLiteral("p7m"), Kleo::Class::CMS | AnyFormat | CipherText},
    {QStringLiteral("p7s"), Kleo::Class::CMS | AnyFormat | AnySignature},
    {QStringLiteral("pem"), Kleo::Class::CMS | Ascii | AnyType | ExamineContentHint},
    {QStringLiteral("pfx"), Kleo::Class::CMS | Binary | Certificate},
    {QStringLiteral("pgp"), Kleo::Class::OpenPGP | Binary | OpaqueSignature | CipherText | AnyCertStoreType | ExamineContentHint},
    {QStringLiteral("sig"), Kleo::Class::OpenPGP | AnyFormat | DetachedSignature},
};

static const QHash<GpgME::Data::Type, unsigned int> gpgmeTypeMap{
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

static const QSet<QString> mimeFileNames{
    /* KMail standard name */
    QStringLiteral("msg.asc"),
    QStringLiteral("smime.p7m"),
    QStringLiteral("openpgp-encrypted-message.asc"),
    /* Old names of internal GpgOL attachments newer versions
     * should use .mime file ending as it is connected with
     * Kleopatra. */
    QStringLiteral("GpgOL_MIME_structure.txt"),
    QStringLiteral("GpgOL_MIME_structure.mime"),
    /* This is gpgtools take on the filename */
    QStringLiteral("OpenPGP encrypted message.asc"),
};

static const unsigned int defaultClassification = NoClass;

template<typename T>
class asKeyValueRange
{
public:
    asKeyValueRange(T &data)
        : m_data{data}
    {
    }

    auto begin()
    {
        return m_data.keyValueBegin();
    }
    auto end()
    {
        return m_data.keyValueEnd();
    }

private:
    T &m_data;
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

static bool mimeTypeInherits(const QMimeType &mimeType, const QString &mimeTypeName)
{
    // inherits is expensive on an invalid mimeType
    return mimeType.isValid() && mimeType.inherits(mimeTypeName);
}

/// Detect either a complete mail file (e.g. mbox or eml file) or a encrypted attachment
/// corresponding to a mail file
static bool isMailFile(const QFileInfo &fi)
{
    static const QRegularExpression attachmentNumbering{QStringLiteral(R"(\([0-9]+\))")};
    const auto fileName = fi.fileName().remove(attachmentNumbering);

    if (mimeFileNames.contains(fileName)) {
        return true;
    }

    {
        Kleo::ClassifyConfig classifyConfig;

        if (classifyConfig.p7mWithoutExtensionAreEmail() && fileName.endsWith(QStringLiteral(".p7m"), Qt::CaseInsensitive)
            && fi.completeSuffix() == fi.suffix()) {
            // match "myfile.p7m" but not "myfile.pdf.p7m"
            return true;
        }
    }

    QMimeDatabase mimeDatabase;
    const auto mimeType = mimeDatabase.mimeTypeForFile(fi);
    return mimeTypeInherits(mimeType, QStringLiteral("message/rfc822")) || mimeTypeInherits(mimeType, QStringLiteral("application/mbox"));
}

static unsigned int classifyExtension(const QFileInfo &fi)
{
    return classifications.value(fi.suffix().toLower(), defaultClassification);
}

unsigned int Kleo::classify(const QString &filename)
{
    const QFileInfo fi(filename);

    if (!fi.exists()) {
        return 0;
    }

    if (isMailFile(fi)) {
        return Kleo::Class::MimeFile | Ascii;
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
    if (classification & Kleo::Class::MimeFile) {
        parts.push_back(QStringLiteral("MimeFile"));
    }
    return parts.join(QLatin1StringView(", "));
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
    for (const auto &[extension, classification] : asKeyValueRange(classifications)) {
        if (classification & DetachedSignature) {
            const QString candidate = signedDataFileName + QLatin1Char('.') + extension;
            if (QFile::exists(candidate)) {
                result.push_back(candidate);
            }
        }
    }
    return result;
}

#ifdef Q_OS_WIN
static QString stripOutlookAttachmentNumbering(const QString &s)
{
    static const QRegularExpression attachmentNumbering{QStringLiteral(R"(\s\([0-9]+\)$)")};
    return QString{s}.remove(attachmentNumbering);
}
#endif

/*!
  \return the (likely) output filename for \a inputFileName, or
  "inputFileName.out" if none can be determined.
*/
QString Kleo::outputFileName(const QString &inputFileName)
{
    const QFileInfo fi(inputFileName);
    const QString suffix = fi.suffix().toLower();

    if (classifications.find(suffix) == std::cend(classifications)) {
        return inputFileName + QLatin1StringView(".out");
    } else {
#ifdef Q_OS_WIN
        return stripOutlookAttachmentNumbering(inputFileName.chopped(suffix.size() + 1));
#else
        return inputFileName.chopped(suffix.size() + 1);
#endif
    }
}

/*!
  \return the commonly used extension for files of type
  \a classification, or NULL if none such exists.
*/
QString Kleo::outputFileExtension(unsigned int classification, bool usePGPFileExt)
{
    if (usePGPFileExt && (classification & Class::OpenPGP) && (classification & Class::Binary)) {
        return QStringLiteral("pgp");
    }

    for (const auto &[extension, classification_] : asKeyValueRange(classifications)) {
        if ((classification_ & classification) == classification) {
            return extension;
        }
    }
    return {};
}

bool Kleo::isFingerprint(const QString &fpr)
{
    static const QRegularExpression fprRegex{QRegularExpression::anchoredPattern(u"[0-9a-fA-F]+"_s)};
    return (fpr.size() == 40 || fpr.size() == 64) && fprRegex.match(fpr).hasMatch();
}

bool Kleo::isChecksumFile(const QString &file)
{
    static bool initialized;
    static QList<QRegularExpression> patterns;
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
                    patterns << QRegularExpression(QRegularExpression::anchoredPattern(pattern), QRegularExpression::CaseInsensitiveOption);
#else
                    patterns << QRegularExpression(QRegularExpression::anchoredPattern(pattern));
#endif
                }
            }
        }
        initialized = true;
    }

    const QString fileName = fi.fileName();
    for (const QRegularExpression &pattern : std::as_const(patterns)) {
        if (pattern.match(fileName).hasMatch()) {
            return true;
        }
    }
    return false;
}
