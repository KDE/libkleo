/*
    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <Libkleo/StringUtils>

#include <QTest>

using namespace Kleo;
using namespace std::literals;

class StringUtilsTest : public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void test_split_data()
    {
        QTest::addColumn<std::string>("sv");
        QTest::addColumn<unsigned>("maxParts");
        QTest::addColumn<std::vector<std::string_view>>("expected");

        QTest::newRow("empty string") << ""s << 0u << std::vector{""sv};
        QTest::newRow("no maximum parts") << "aa b ccc dd  e"s << 0u << std::vector{"aa"sv, "b"sv, "ccc"sv, "dd"sv, ""sv, "e"sv};
        QTest::newRow("at most 10 parts") << "aa b ccc dd  e"s << 10u << std::vector({"aa"sv, "b"sv, "ccc"sv, "dd"sv, ""sv, "e"sv});
        QTest::newRow("at most 6 parts") << "aa b ccc dd  e"s << 6u << std::vector({"aa"sv, "b"sv, "ccc"sv, "dd"sv, ""sv, "e"sv});
        QTest::newRow("at most 5 parts") << "aa b ccc dd  e"s << 5u << std::vector({"aa"sv, "b"sv, "ccc"sv, "dd"sv, " e"sv});
        QTest::newRow("at most 3 parts") << "aa b ccc dd  e"s << 3u << std::vector({"aa"sv, "b"sv, "ccc dd  e"sv});
        QTest::newRow("at most 1 parts") << "aa b ccc dd  e"s << 1u << std::vector({"aa b ccc dd  e"sv});
        QTest::newRow("leading and trailing separator") << " a b "s << 0u << std::vector({""sv, "a"sv, "b"sv, ""sv});
    }

    void test_split()
    {
        QFETCH(std::string, sv);
        QFETCH(unsigned, maxParts);
        QFETCH(std::vector<std::string_view>, expected);

        if (maxParts == 0) {
            QCOMPARE(Kleo::split(sv, ' '), expected);
        } else {
            QCOMPARE(Kleo::split(sv, ' ', maxParts), expected);
        }
    }

    void test_toStrings_data()
    {
        QTest::addColumn<std::vector<std::string_view>>("input");
        QTest::addColumn<std::vector<std::string>>("expected");

        QTest::newRow("empty") << std::vector<std::string_view>() << std::vector<std::string>();
        QTest::newRow("1 element") << std::vector{"aa"sv} << std::vector{"aa"s};
        QTest::newRow("3 elements") << std::vector{"aa"sv, "b"sv, "ccc"sv} << std::vector{"aa"s, "b"s, "ccc"s};
    }

    void test_toStrings()
    {
        QFETCH(std::vector<std::string_view>, input);
        QFETCH(std::vector<std::string>, expected);

        QCOMPARE(Kleo::toStrings(input), expected);
    }
};

QTEST_MAIN(StringUtilsTest)
#include "stringutilstest.moc"
