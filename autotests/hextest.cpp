/*
    autotests/hextest.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <Libkleo/Hex>

#include <QTest>

using namespace Kleo;

namespace QTest
{
template <>
inline char *toString(const std::string &s)
{
    return qstrdup(('"' + s + '"').c_str());
}
}

class HexTest: public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void test_hexdecode()
    {
        QCOMPARE(hexdecode(nullptr), std::string{});
        QCOMPARE(hexdecode(std::string{}), std::string{});
        QCOMPARE(hexdecode(QByteArray{}), QByteArray{});

        QCOMPARE(hexdecode(""), std::string{});
        QCOMPARE(hexdecode(std::string{""}), std::string{});
        QCOMPARE(hexdecode(QByteArray{""}), QByteArray{});

        QCOMPARE(hexdecode("0123456789"), std::string{"0123456789"});
        QCOMPARE(hexdecode(std::string{"0123456789"}), std::string{"0123456789"});
        QCOMPARE(hexdecode(QByteArray{"0123456789"}), QByteArray{"0123456789"});

        QCOMPARE(hexdecode("%20"), std::string{" "});
        QCOMPARE(hexdecode(std::string{"%20"}), std::string{" "});
        QCOMPARE(hexdecode(QByteArray{"%20"}), QByteArray{" "});

        QCOMPARE(hexdecode("+"), std::string{" "});
        QCOMPARE(hexdecode(std::string{"+"}), std::string{" "});
        QCOMPARE(hexdecode(QByteArray{"+"}), QByteArray{" "});
    }
};

QTEST_MAIN(HexTest)
#include "hextest.moc"
