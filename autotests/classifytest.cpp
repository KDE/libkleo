/*
    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Carl Schwan <carl@carlschwan.eu>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include <Libkleo/Classify>
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

    void identifyMimeFileExtensionTest()
    {
        QTemporaryFile mbox;
        mbox.setFileTemplate("XXXXXX.mbox");
        QVERIFY(mbox.open());
        QVERIFY(Kleo::isMimeFile(Kleo::classify(mbox.fileName())));

        QTemporaryFile eml;
        eml.setFileTemplate("XXXXXX.eml");
        QVERIFY(eml.open());
        QVERIFY(Kleo::isMimeFile(Kleo::classify(eml.fileName())));

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

        QFileInfo fi(sig.fileName());

        QCOMPARE(fi.path() + QLatin1Char('/') + fi.baseName(), Kleo::outputFileName(sig.fileName()));
    }
};

QTEST_MAIN(ClassifyTest)
#include "classifytest.moc"
