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

        QByteArray allCharsExceptControlCharsAndSpaceAndPlus{256 - 32 - 1 - 1, Qt::Uninitialized};
        // initialize the start of allCharsExceptControlCharsAndSpaceAndPlus with the characters from '!' to '*' (the one before '+')
        std::iota(allCharsExceptControlCharsAndSpaceAndPlus.begin(), allCharsExceptControlCharsAndSpaceAndPlus.begin() + ('+' - '!'), '!');
        // initialize the rest of allCharsExceptControlCharsAndSpaceAndPlus with the characters from ',' (the one after '+') to '\xFF'
        std::iota(allCharsExceptControlCharsAndSpaceAndPlus.begin() + ('+' - '!'), allCharsExceptControlCharsAndSpaceAndPlus.end(), ',');

        QByteArray allControlChars{32, Qt::Uninitialized};
        std::iota(allControlChars.begin(), allControlChars.end(), 0);
        QTest::newRow("empty string") << ""_ba << ""_ba;
        QTest::newRow("nothing to escape") << allCharsExceptControlCharsAndSpaceAndPlus << allCharsExceptControlCharsAndSpaceAndPlus;
        QTest::newRow("control chars are percent-escaped")
            << allControlChars << "%00%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F"_ba;
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
