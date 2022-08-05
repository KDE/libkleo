/*
    utils/algorithm.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <algorithm>
#include <iterator>

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

template<typename Container, typename UnaryOperation>
Container transformInPlace(Container &&c, UnaryOperation op)
{
    std::transform(std::begin(c), std::end(c), std::begin(c), op);
    return std::move(c);
}

/** Convenience helper for checking if the predicate @p p returns @c true
 *  for all elements in the range @p range. Returns @c true if the range is empty.
 *  Use ranges::all_of() instead if you can use C++20.
 */
template<typename InputRange, typename UnaryPredicate>
bool all_of(const InputRange &range, UnaryPredicate p)
{
    return std::all_of(std::begin(range), std::end(range), p);
}

/** Convenience helper for checking if a @p range contains at least one element
 *  for which predicate @p p returns @c true. Returns @c false if @p range is
 *  empty.
 *  Use ranges::any_of() instead if you can use C++20.
 */
template<typename InputRange, typename UnaryPredicate>
bool any_of(const InputRange &range, UnaryPredicate p)
{
    return std::any_of(std::begin(range), std::end(range), p);
}

/** Convenience helper for checking if a @p container contains an element
 *  with key equivalent to @p key. This is mainly meant to be used for the
 *  associative standard containers until we can use their corresponding
 *  member function in C++20.
 */
template<typename Container, typename Key>
bool contains(const Container &container, const Key &key)
{
    return std::find(std::begin(container), std::end(container), key) != std::end(container);
}

/** Convenience helper for checking if a @p container contains an element
 *  for which predicate @p p returns @c true.
 */
template<typename Container, typename UnaryPredicate>
bool contains_if(const Container &container, UnaryPredicate p)
{
    return std::find_if(std::begin(container), std::end(container), p) != std::end(container);
}

/**
 * Convenience helper for removing elements from a vector @p v for which
 * predicate @p p returns @c true.
 * Use std::erase_if() instead if you can use C++20.
 */
template<typename Vector, typename UnaryPredicate>
void erase_if(Vector &v, UnaryPredicate p)
{
    v.erase(std::remove_if(std::begin(v), std::end(v), p), std::end(v));
}

}
