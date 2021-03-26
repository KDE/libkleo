/*
    utils/algorithm.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifndef LIBKLEO_ALGORITHM_H
#define LIBKLEO_ALGORITHM_H

#include <algorithm>

namespace Kleo
{

template<typename ForwardIterator, typename T>
ForwardIterator binary_find(ForwardIterator first, ForwardIterator last, const T &value)
{
    const ForwardIterator it = std::lower_bound(first, last, value);
    return (it == last || value < *it) ? last : it;
}

template<typename ForwardIterator, typename T, typename Compare>
ForwardIterator binary_find(ForwardIterator first, ForwardIterator last, const T &value, Compare comp)
{
    const ForwardIterator it = std::lower_bound(first, last, value, comp);
    return (it == last || comp(value, *it)) ? last : it;
}

}

#endif // LIBKLEO_ALGORITHM_H
