/* -*- mode: c++; c-basic-offset:4 -*-
    utils/classify.cpp

    This file is part of Kleopatra, the KDE keymanager
    Copyright (c) 2007 Klarälvdalens Datakonsult AB

    Kleopatra is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kleopatra is distributed in the hope that it will be useful,
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

#include "classify.h"

#include "libkleo_debug.h"
#include "kleo/checksumdefinition.h"

#include <QString>
#include <QStringList>
#include <QFile>
#include <QFileInfo>
#include <QtAlgorithms>
#include <QByteArrayMatcher>
#include <QMap>
#include <QRegularExpression>

#include <gpgme++/data.h>
#include <qgpgme/dataprovider.h>

#include <iterator>
#include <functional>

using namespace Kleo::Class;

namespace
{

const unsigned int ExamineContentHint = 0x8000;

static const struct _classification {
    char extension[4];
    unsigned int classification;
} classifications[] = {
    // ordered by extension
    { "arl", CMS    | Binary  | CertificateRevocationList },
    { "asc", OpenPGP |  Ascii  | OpaqueSignature | DetachedSignature | CipherText | AnyCertStoreType | ExamineContentHint },
    { "cer", CMS    | Binary  | Certificate },
    { "crl", CMS    | Binary  | CertificateRevocationList },
    { "crt", CMS    | Binary  | Certificate },
    { "der", CMS    | Binary  | Certificate | CertificateRevocationList },
    { "gpg", OpenPGP | Binary  | OpaqueSignature | CipherText | AnyCertStoreType | ExamineContentHint},
    { "p10", CMS    |  Ascii  | CertificateRequest },
    { "p12", CMS    | Binary  | ExportedPSM },
    { "p7c", CMS    | Binary  | Certificate  },
    { "p7m", CMS    | Binary  | CipherText },
    { "p7s", CMS    | Binary  | AnySignature },
    { "pem", CMS    |  Ascii  | AnyType | ExamineContentHint },
    { "pfx", CMS    | Binary  | Certificate },
    { "pgp", OpenPGP | Binary  | OpaqueSignature | CipherText | AnyCertStoreType | ExamineContentHint},
    { "sig", OpenPGP | AnyFormat | DetachedSignature },
};

static const QMap<GpgME::Data::Type, unsigned int> gpgmeTypeMap {
    { GpgME::Data::PGPSigned, OpenPGP | OpaqueSignature },
    /* PGPOther might be just an unencrypted unsigned pgp message. Decrypt
     * would yield the plaintext anyway so for us this is CipherText. */
    { GpgME::Data::PGPOther, OpenPGP | CipherText },
    { GpgME::Data::PGPKey, OpenPGP | Certificate },
    { GpgME::Data::CMSSigned, CMS | AnySignature },
    { GpgME::Data::CMSEncrypted, CMS | CipherText },
    /* See PGPOther */
    { GpgME::Data::CMSOther, CMS | CipherText },
    { GpgME::Data::X509Cert, CMS | Certificate},
    { GpgME::Data::PKCS12, CMS | Binary | ExportedPSM },
    { GpgME::Data::PGPEncrypted, OpenPGP | CipherText },
    { GpgME::Data::PGPSignature, OpenPGP | DetachedSignature },
};

static const unsigned int defaultClassification = NoClass;

template <template <typename U> class Op>
struct ByExtension {
    typedef bool result_type;

    template <typename T>
    bool operator()(const T &lhs, const T &rhs) const
    {
        return Op<int>()(qstricmp(lhs.extension, rhs.extension), 0);
    }
    template <typename T>
    bool operator()(const T &lhs, const char *rhs) const
    {
        return Op<int>()(qstricmp(lhs.extension, rhs), 0);
    }
    template <typename T>
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
    { "CERTIFICATE",       Certificate },
    { "ENCRYPTED MESSAGE", CipherText  },
    { "MESSAGE",           OpaqueSignature | CipherText },
    { "PKCS12",            ExportedPSM },
    { "PRIVATE KEY BLOCK", ExportedPSM },
    { "PUBLIC KEY BLOCK",  Certificate },
    { "SIGNATURE",         DetachedSignature },
    { "SIGNED MESSAGE",    ClearsignedMessage | DetachedSignature },
};

template <template <typename U> class Op>
struct ByContent {
    typedef bool result_type;

    const unsigned int N;
    explicit ByContent(unsigned int n) : N(n) {}

    template <typename T>
    bool operator()(const T &lhs, const T &rhs) const
    {
        return Op<int>()(qstrncmp(lhs.content, rhs.content, N), 0);
    }
    template <typename T>
    bool operator()(const T &lhs, const char *rhs) const
    {
        return Op<int>()(qstrncmp(lhs.content, rhs, N), 0);
    }
    template <typename T>
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
    const _classification *const it = qBinaryFind(std::begin(classifications), std::end(classifications),
                                      fi.suffix().toLatin1().constData(),
                                      ByExtension<std::less>());
    if (it != std::end(classifications))
        if (!(it->classification & ExamineContentHint)) {
            return it->classification;
        }

    return it == std::end(classifications) ? defaultClassification
                                        : it->classification;
}

unsigned int Kleo::classify(const QString &filename)
{
    Q_ASSERT(std::is_sorted(std::begin(classifications), std::end(classifications), ByExtension<std::less>()));

    const QFileInfo fi(filename);

    if (!fi.exists()) {
        return 0;
    }

    QFile file(filename);
    /* The least reliable but always availabe classification */
    const unsigned int extClass = classifyExtension(fi);
    if (!GpgME::hasFeature(0, GpgME::BinaryAndFineGrainedIdentify) &&
        !(extClass & ExamineContentHint)) {
        /* GpgME's identfiy and our internal Classify were so incomplete
         * before BinaryAndFineGrainedIdentify that we are better of
         * to just use the file extension if ExamineContentHint is not set. */
        qCDebug(LIBKLEO_LOG) << "Classified based only on extension.";
        return extClass;
    }

    if (!file.open(QIODevice::ReadOnly)) {
        qCDebug(LIBKLEO_LOG) << "Failed to open file: " << filename << " for classification.";
        return extClass;
    }

    /* More reliable */
    const unsigned int contentClass = classifyContent(file.read(4096));
    if (contentClass != defaultClassification) {
        qCDebug(LIBKLEO_LOG) << "Classified based on content.";
        return contentClass;
    }

    /* Probably some X509 Stuff that GpgME in it's wisdom does not handle. Again
     * file extension is probably more reliable as the last resort. */
    qCDebug(LIBKLEO_LOG) << "No classification based on content.";
    return extClass;
}

static unsigned int classifyContentInteral(const QByteArray &data)
{
    Q_ASSERT(std::is_sorted(std::begin(content_classifications), std::end(content_classifications), ByContent<std::less>(100)));

    static const char beginString[] = "-----BEGIN ";
    static const QByteArrayMatcher beginMatcher(beginString);
    int pos = beginMatcher.indexIn(data);
    if (pos < 0) {
        return defaultClassification;
    }
    pos += sizeof beginString - 1;

    const bool pgp = qstrncmp(data.data() + pos, "PGP ", 4) == 0;
    if (pgp) {
        pos += 4;
    }

    const int epos = data.indexOf("-----\n", pos);
    if (epos < 0) {
        return defaultClassification;
    }

    const _content_classification *const cit
        = qBinaryFind(std::begin(content_classifications), std::end(content_classifications),
                      data.data() + pos, ByContent<std::less>(epos - pos));

    if (cit != std::end(content_classifications)) {
        return cit->classification | (pgp ? OpenPGP : CMS);
    }
    return defaultClassification;
}

unsigned int Kleo::classifyContent(const QByteArray &data)
{
    /* As of Version 1.6.0 GpgME does not distinguish between detached
     * signatures and signatures. So we prefer kleo's classification and
     * only use gpgme as fallback.
     * With newer versions we have a better identify that really inspects
     * the PGP Packages. Which is by far the most reliable classification.
     * So this is already used for the default classification. File extensions
     * and our classifyinternal is only used as a fallback.
     */
    if (!GpgME::hasFeature(0, GpgME::BinaryAndFineGrainedIdentify)) {
        unsigned int ourClassification = classifyContentInteral(data);
        if (ourClassification != defaultClassification) {
            return ourClassification;
        }
    }
    QGpgME::QByteArrayDataProvider dp(data);
    GpgME::Data gpgmeData(&dp);
    GpgME::Data::Type type = gpgmeData.type();

    return gpgmeTypeMap.value(type, defaultClassification);
}

QString Kleo::printableClassification(unsigned int classification)
{
    QStringList parts;
    if (classification & CMS) {
        parts.push_back(QStringLiteral("CMS"));
    }
    if (classification & OpenPGP) {
        parts.push_back(QStringLiteral("OpenPGP"));
    }
    if (classification & Binary) {
        parts.push_back(QStringLiteral("Binary"));
    }
    if (classification & Ascii) {
        parts.push_back(QStringLiteral("Ascii"));
    }
    if (classification & DetachedSignature) {
        parts.push_back(QStringLiteral("DetachedSignature"));
    }
    if (classification & OpaqueSignature) {
        parts.push_back(QStringLiteral("OpaqueSignature"));
    }
    if (classification & ClearsignedMessage) {
        parts.push_back(QStringLiteral("ClearsignedMessage"));
    }
    if (classification & CipherText) {
        parts.push_back(QStringLiteral("CipherText"));
    }
    if (classification & Certificate) {
        parts.push_back(QStringLiteral("Certificate"));
    }
    if (classification & ExportedPSM) {
        parts.push_back(QStringLiteral("ExportedPSM"));
    }
    if (classification & CertificateRequest) {
        parts.push_back(QStringLiteral("CertificateRequest"));
    }
    return parts.join(QStringLiteral(", "));
}

static QString chopped(QString s, unsigned int n)
{
    s.chop(n);
    return s;
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
    const QString baseName = chopped(signatureFileName, 4);
    return QFile::exists(baseName) ? baseName : QString();
}

/*!
  \return all (existing) candiate signature files for \a signedDataFileName

  Note that there can very well be more than one such file, e.g. if
  the same data file was signed by both CMS and OpenPGP certificates.
*/
QStringList Kleo::findSignatures(const QString &signedDataFileName)
{
    QStringList result;
    for (unsigned int i = 0, end = sizeof(classifications) / sizeof(_classification); i < end; ++i)
        if (classifications[i].classification & DetachedSignature) {
            const QString candiate = signedDataFileName + QLatin1Char('.') + QLatin1String(classifications[i].extension);
            if (QFile::exists(candiate)) {
                result.push_back(candiate);
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

    if (qBinaryFind(std::begin(classifications), std::end(classifications),
                    fi.suffix().toLatin1().constData(),
                    ByExtension<std::less>()) == std::end(classifications)) {
        return inputFileName + QLatin1String(".out");
    } else {
        return chopped(inputFileName, 4);
    }
}

/*!
  \return the commonly used extension for files of type
  \a classification, or NULL if none such exists.
*/
const char *Kleo::outputFileExtension(unsigned int classification, bool usePGPFileExt)
{

    if (classification & OpenPGP && usePGPFileExt) {
        return "pgp";
    }

    for (unsigned int i = 0; i < sizeof classifications / sizeof * classifications; ++i)
        if ((classifications[i].classification & classification) == classification) {
            return classifications[i].extension;
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
        Q_FOREACH (const std::shared_ptr<ChecksumDefinition> &cd, ChecksumDefinition::getChecksumDefinitions()) {
            if (cd) {
                Q_FOREACH (const QString &pattern, cd->patterns()) {
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
    Q_FOREACH (const QRegExp &pattern, patterns) {
        if (pattern.exactMatch(fileName)) {
            return true;
        }
    }
    return false;
}
