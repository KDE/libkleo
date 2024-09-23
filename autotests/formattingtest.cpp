/*
    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include <Libkleo/Formatting>

#include <QTest>

using namespace Kleo;
using namespace Qt::Literals::StringLiterals;

class FormattingTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void test_prettyID_data()
    {
        QTest::addColumn<QByteArray>("id");
        QTest::addColumn<QString>("expected");

        QTest::newRow("empty string") //
            << ""_ba //
            << u""_s;
        QTest::newRow("short key ID") //
            << "01234567"_ba //
            << u"0123 4567"_s;
        QTest::newRow("key ID") //
            << "0123456789abcdef"_ba //
            << u"0123 4567 89AB CDEF"_s;
        QTest::newRow("V4 fingerprint") //
            << "0000111122223333444455556666777788889999"_ba //
            << u"0000 1111 2222 3333 4444  5555 6666 7777 8888 9999"_s;
        QTest::newRow("V5 fingerprint") //
            << "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"_ba //
            << u"00001 11122 22333 34444 55556 66677 77888 89999 AAAAB BBBCC"_s;
        QTest::newRow("string with length != 4*n") //
            << "0123456789abcd"_ba //
            << u"0123 4567 89AB CD"_s;
    }

    void test_prettyID()
    {
        QFETCH(QByteArray, id);
        QFETCH(QString, expected);

        QCOMPARE(Formatting::prettyID(id.constData()), expected);
    }

    void test_accessibleHexID_data()
    {
        QTest::addColumn<QByteArray>("id");
        QTest::addColumn<QString>("expected");

        QTest::newRow("empty string") //
            << ""_ba //
            << u""_s;
        QTest::newRow("short key ID") //
            << "01234567"_ba //
            << u"0 1 2 3, 4 5 6 7"_s;
        QTest::newRow("key ID") //
            << "0123456789abcdef"_ba //
            << u"0 1 2 3, 4 5 6 7, 8 9 a b, c d e f"_s;
        QTest::newRow("V4 fingerprint") //
            << "0000111122223333444455556666777788889999"_ba //
            << u"0 0 0 0, 1 1 1 1, 2 2 2 2, 3 3 3 3, 4 4 4 4, 5 5 5 5, 6 6 6 6, 7 7 7 7, 8 8 8 8, 9 9 9 9"_s;
        QTest::newRow("V5 fingerprint") //
            << "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"_ba //
            << u"0 0 0 0 1, 1 1 1 2 2, 2 2 3 3 3, 3 4 4 4 4, 5 5 5 5 6, 6 6 6 7 7, 7 7 8 8 8, 8 9 9 9 9, a a a a b, b b b c c"_s;
        QTest::newRow("string with length != 4*n") //
            << "0123456789abcd"_ba //
            << u"0123456789abcd"_s;
    }

    void test_accessibleHexID()
    {
        QFETCH(QByteArray, id);
        QFETCH(QString, expected);

        QCOMPARE(Formatting::accessibleHexID(id.constData()), expected);
    }
};

QTEST_MAIN(FormattingTest)
#include "formattingtest.moc"
