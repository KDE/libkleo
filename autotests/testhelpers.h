/*
    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include <Libkleo/Chrono>
#include <Libkleo/ExpiryChecker>

#include <QTest>

#include <gpgme++/key.h>

namespace QTest
{

// allow comparing QString to const char * and vice versa
inline bool qCompare(QString const &t1, const char *t2, const char *actual, const char *expected, const char *file, int line)
{
    return qCompare(t1, QString::fromLatin1(t2), actual, expected, file, line);
}
inline bool qCompare(const char *t1, QString const &t2, const char *actual, const char *expected, const char *file, int line)
{
    return qCompare(QString::fromLatin1(t1), t2, actual, expected, file, line);
}

inline bool qCompare(const GpgME::Key &key1, const GpgME::Key &key2, const char *actual, const char *expected, const char *file, int line)
{
    return qCompare(key1.primaryFingerprint(), key2.primaryFingerprint(), actual, expected, file, line);
}

template<>
inline char *toString(const Kleo::chrono::days &days)
{
    return QTest::toString(days.count() == 1 ? QByteArray{"1 day"} : QByteArray::number(qlonglong{days.count()}) + " days");
}

// helpers to compare CheckFlags with CheckFlag; the generic template falls back to integer comparison which doesn't give nice value output
inline bool qCompare(const Kleo::ExpiryChecker::CheckFlags &t1, //
                     Kleo::ExpiryChecker::CheckFlag t2,
                     const char *actual,
                     const char *expected,
                     const char *file,
                     int line)
{
    return qCompare(t1, Kleo::ExpiryChecker::CheckFlags{t2}, actual, expected, file, line);
}
inline bool qCompare(Kleo::ExpiryChecker::CheckFlag t1, //
                     const Kleo::ExpiryChecker::CheckFlags &t2,
                     const char *actual,
                     const char *expected,
                     const char *file,
                     int line)
{
    return qCompare(Kleo::ExpiryChecker::CheckFlags{t1}, t2, actual, expected, file, line);
}

}
