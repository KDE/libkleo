/*
    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2025 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <Libkleo/Assuan>

#include <QTest>

using namespace Qt::StringLiterals;

class AssuanTest : public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void test_escapeAttributeValue_data()
    {
        QTest::addColumn<QByteArray>("input");
        QTest::addColumn<QByteArray>("expected");

        QByteArray allCharsExceptControlCharsAndSpaceAndPercentAndPlus{256 - 32 - 1 - 1 - 1, Qt::Uninitialized};
        // initialize the first 4 characters with the characters from '!' to '$' (the one before '%'), i.e. 0x21...0x24
        std::iota(allCharsExceptControlCharsAndSpaceAndPercentAndPlus.begin(), allCharsExceptControlCharsAndSpaceAndPercentAndPlus.begin() + 4, '!');
        // initialize the next 5 characters with the characters from '&' (the one after '%') to '*' (the one before '+'), i.e. 0x26...0x2A
        std::iota(allCharsExceptControlCharsAndSpaceAndPercentAndPlus.begin() + 4, allCharsExceptControlCharsAndSpaceAndPercentAndPlus.begin() + 9, '&');
        // initialize the remaining characters with the characters from ',' (the one after '+'), i.e. 0x2C...0xFF
        std::iota(allCharsExceptControlCharsAndSpaceAndPercentAndPlus.begin() + 9, allCharsExceptControlCharsAndSpaceAndPercentAndPlus.end(), ',');

        QByteArray allControlChars{32, Qt::Uninitialized};
        std::iota(allControlChars.begin(), allControlChars.end(), 0);
        QTest::newRow("empty string") << ""_ba << ""_ba;
        QTest::newRow("nothing to escape") << allCharsExceptControlCharsAndSpaceAndPercentAndPlus << allCharsExceptControlCharsAndSpaceAndPercentAndPlus;
        QTest::newRow("control chars are percent-escaped")
            << allControlChars << "%00%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F"_ba;
        QTest::newRow("percent is percent-escaped") << "%"_ba << "%25"_ba;
        QTest::newRow("plus is percent-escaped") << "+"_ba << "%2B"_ba;
        QTest::newRow("space is plus-escaped") << " "_ba << "+"_ba;
    }

    void test_escapeAttributeValue()
    {
        QFETCH(QByteArray, input);
        QFETCH(QByteArray, expected);

        QCOMPARE(Kleo::Assuan::escapeAttributeValue(input), expected);
    }
};

QTEST_MAIN(AssuanTest)
#include "assuantest.moc"
