/*
    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Carl Schwan <carl@carlschwan.eu>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include <Libkleo/Classify>
#include <QTemporaryDir>
#include <QTemporaryFile>
#include <QTest>

class ClassifyTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase()
    {
    }

    void cleanupTestCase()
    {
    }

    void identifyFileName()
    {
        QTemporaryDir dir;

        const auto fileName = dir.filePath(QStringLiteral("msg.asc"));
        const auto fileName1 = dir.filePath(QStringLiteral("msg(1).asc"));
        {
            QFile asc(fileName);
            QVERIFY(asc.open(QIODevice::WriteOnly));

            QFile asc1(fileName1);
            QVERIFY(asc1.open(QIODevice::WriteOnly));
        }

        QVERIFY(Kleo::isMimeFile(Kleo::classify(fileName)));
        QVERIFY(Kleo::isMimeFile(fileName1));
    }

    void identifyMimeFileExtensionTest()
    {
        {
            QTemporaryFile mbox;
            mbox.setFileTemplate("XXXXXX.mbox");
            QVERIFY(mbox.open());
            QVERIFY(Kleo::mayBeMimeFile(Kleo::classify(mbox.fileName())));
        }

        {
            QTemporaryFile eml;
            eml.setFileTemplate("XXXXXX.eml");
            QVERIFY(eml.open());
            QVERIFY(Kleo::mayBeMimeFile(eml.fileName()));

            QCOMPARE(QStringLiteral("Ascii, MimeFile"), Kleo::printableClassification(Kleo::classify(eml.fileName())));
        }

        {
            QTemporaryFile myFile;
            myFile.setFileTemplate("XXXXXX.p7m");
            QVERIFY(myFile.open());
            QVERIFY(Kleo::mayBeMimeFile(myFile.fileName()));
        }

        {
            QTemporaryFile myPdfFile;
            myPdfFile.setFileTemplate("XXXXXX.pdf.p7m");
            QVERIFY(myPdfFile.open());
            QVERIFY(!Kleo::mayBeMimeFile(myPdfFile.fileName()));
        }
    }

    void identifyCertificateStoreExtensionTest()
    {
        QTemporaryFile crl;
        crl.setFileTemplate("XXXXXX.crl");
        QVERIFY(crl.open());
        QVERIFY(Kleo::isCertificateRevocationList(crl.fileName()));
    }

    void findSignaturesTest()
    {
        QTemporaryFile sig;
        sig.setFileTemplate("XXXXXX.sig");
        QVERIFY(sig.open());

        QFileInfo fi(sig.fileName());

        const auto signatures = Kleo::findSignatures(fi.baseName());
        QCOMPARE(1, signatures.count());
        QCOMPARE(fi.baseName() + QStringLiteral(".sig"), signatures[0]);
    }

    void findOutputFileNameNotFoundTest()
    {
        QTemporaryFile unknown;
        unknown.setFileTemplate("XXXXXX.unknown");
        QVERIFY(unknown.open());

        QCOMPARE(unknown.fileName() + QStringLiteral(".out"), Kleo::outputFileName(unknown.fileName()));
    }

    void findOutputFileNameTest()
    {
        QTemporaryFile sig;
        sig.setFileTemplate("XXXXXX.sig");
        QVERIFY(sig.open());

        QCOMPARE(sig.fileName().chopped(4), Kleo::outputFileName(sig.fileName()));
    }

    void test_outputFileExtension()
    {
        QCOMPARE(Kleo::outputFileExtension(Kleo::Class::OpenPGP | Kleo::Class::CipherText | Kleo::Class::Binary, false), QStringLiteral("gpg"));
        QCOMPARE(Kleo::outputFileExtension(Kleo::Class::OpenPGP | Kleo::Class::CipherText | Kleo::Class::Binary, true), QStringLiteral("pgp"));
        QCOMPARE(Kleo::outputFileExtension(Kleo::Class::OpenPGP | Kleo::Class::CipherText | Kleo::Class::Ascii, false), QStringLiteral("asc"));
        QCOMPARE(Kleo::outputFileExtension(Kleo::Class::OpenPGP | Kleo::Class::CipherText | Kleo::Class::Ascii, true), QStringLiteral("asc"));

        QCOMPARE(Kleo::outputFileExtension(Kleo::Class::OpenPGP | Kleo::Class::DetachedSignature | Kleo::Class::Binary, false), QStringLiteral("sig"));
        QCOMPARE(Kleo::outputFileExtension(Kleo::Class::OpenPGP | Kleo::Class::DetachedSignature | Kleo::Class::Binary, true), QStringLiteral("pgp"));
        QCOMPARE(Kleo::outputFileExtension(Kleo::Class::OpenPGP | Kleo::Class::DetachedSignature | Kleo::Class::Ascii, false), QStringLiteral("asc"));
        QCOMPARE(Kleo::outputFileExtension(Kleo::Class::OpenPGP | Kleo::Class::DetachedSignature | Kleo::Class::Ascii, true), QStringLiteral("asc"));

        QCOMPARE(Kleo::outputFileExtension(Kleo::Class::CMS | Kleo::Class::CipherText | Kleo::Class::Binary, false), QStringLiteral("p7m"));
        QCOMPARE(Kleo::outputFileExtension(Kleo::Class::CMS | Kleo::Class::CipherText | Kleo::Class::Ascii, false), QStringLiteral("p7m"));
        QCOMPARE(Kleo::outputFileExtension(Kleo::Class::CMS | Kleo::Class::DetachedSignature | Kleo::Class::Binary, false), QStringLiteral("p7s"));
        QCOMPARE(Kleo::outputFileExtension(Kleo::Class::CMS | Kleo::Class::DetachedSignature | Kleo::Class::Ascii, false), QStringLiteral("p7s"));
    }
};

QTEST_MAIN(ClassifyTest)
#include "classifytest.moc"
