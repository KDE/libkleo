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

using namespace Qt::Literals::StringLiterals;

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

    void test_mayBeMimeFile_fileName_data()
    {
        QTest::addColumn<QString>("fileName");
        QTest::addColumn<bool>("result");

        QTest::newRow("*.mbox") << u"XXXXXX.mbox"_s << true;
        QTest::newRow("*.eml") << u"XXXXXX.eml"_s << true;
        QTest::newRow("*.p7m") << u"XXXXXX.p7m"_s << true;
        QTest::newRow("*.P7M") << u"XXXXXX.P7M"_s << true;
        QTest::newRow("*.pdf.p7m") << u"XXXXXX.pdf.p7m"_s << false;
    }

    void test_mayBeMimeFile_fileName()
    {
        QFETCH(QString, fileName);
        QFETCH(bool, result);

        QTemporaryFile tempfile;
        tempfile.setFileTemplate(fileName);
        QVERIFY(tempfile.open());
        QCOMPARE(Kleo::mayBeMimeFile(tempfile.fileName()), result);
    }

    void test_mayBeMimeFile_classification()
    {
        QVERIFY(Kleo::mayBeMimeFile(Kleo::Class::MimeFile | Kleo::Class::Ascii));
    }

    void test_printableClassification()
    {
        QTemporaryFile eml;
        eml.setFileTemplate("XXXXXX.eml");
        QVERIFY(eml.open());

        QCOMPARE(QStringLiteral("Ascii, MimeFile"), Kleo::printableClassification(Kleo::classify(eml.fileName())));
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

    void test_outputFileName_data()
    {
        QTest::addColumn<QString>("fileName");
        QTest::addColumn<QString>("result");

        QTest::newRow("known extension") << u"XXXXXX.sig"_s << u"XXXXXX"_s;
        QTest::newRow("unknown extension") << u"XXXXXX.unknown"_s << u"XXXXXX.unknown.out"_s;
        QTest::newRow("upper-case extension") << u"XXXXXX.GPG"_s << u"XXXXXX"_s;
    }

    void test_outputFileName()
    {
        QFETCH(QString, fileName);
        QFETCH(QString, result);

        QCOMPARE(Kleo::outputFileName(fileName), result);
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

    void test_isFingerprint()
    {
        QVERIFY(Kleo::isFingerprint(u"0123456789ABCDEF0123456789abcdef01234567"_s)); // V4 fingerprint
        QVERIFY(Kleo::isFingerprint(u"0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef"_s)); // V5 fingerprint

        // wrong size
        QVERIFY(!Kleo::isFingerprint(QString{}));
        QVERIFY(!Kleo::isFingerprint(u"0123456789ABCDEF"_s));
        QVERIFY(!Kleo::isFingerprint(u"0123456789ABCDEF0123456789abcdef0123456"_s));
        QVERIFY(!Kleo::isFingerprint(u"0123456789ABCDEF0123456789abcdef012345678"_s));
        QVERIFY(!Kleo::isFingerprint(u"0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcde"_s));
        QVERIFY(!Kleo::isFingerprint(u"0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef0"_s));

        // wrong characters
        QVERIFY(!Kleo::isFingerprint(u"0123456789ABCDEF 0123456789abcdef0123456"_s));
        QVERIFY(!Kleo::isFingerprint(u"0123456789ABCDEFg0123456789abcdef0123456"_s));
    }
};

QTEST_MAIN(ClassifyTest)
#include "classifytest.moc"
