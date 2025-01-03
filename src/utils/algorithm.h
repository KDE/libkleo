/*
    utils/algorithm.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <algorithm>
#include <functional>
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

/** Convenience helper for counting the number of elements in the range @p range
 *  for which the predicate @p p returns @c true.
 *  Use ranges::count_if() instead if you can use C++20.
 */
template<typename InputRange, typename UnaryPredicate>
auto count_if(const InputRange &range, UnaryPredicate p)
{
    return std::count_if(std::begin(range), std::end(range), p);
}

/** Convenience helper for finding the first element in the range @p range
 *  for which predicate @p p returns @c true.
 *  Use ranges::find_if() instead if you can use C++20.
 */
template<typename InputRange, typename UnaryPredicate>
auto find_if(const InputRange &range, UnaryPredicate p)
{
    return std::find_if(std::begin(range), std::end(range), p);
}

/** Convenience helper for applying the function @p f on all elements of the
 *  range @p range.
 *  Use ranges::for_each() instead if you can use C++20.
 */
template<typename InputRange, typename UnaryFunction>
UnaryFunction for_each(const InputRange &range, UnaryFunction f)
{
    return std::for_each(std::begin(range), std::end(range), f);
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

/** Convenience helper for checking if a range @p range contains an element
 *  for which predicate @p p returns @c true.
 */
template<typename InputRange, typename UnaryPredicate>
bool contains_if(const InputRange &range, UnaryPredicate p)
{
    return Kleo::find_if(range, p) != std::end(range);
}

/**
 * Convenience helper for copying elements of @p range.
 * Use std::ranges::copy_if() instead if you can use C++20.
 */
template<typename InputRange, typename OutputIterator, typename UnaryPredicate>
OutputIterator copy(InputRange &&range, OutputIterator result)
{
    return std::copy(std::begin(range), std::end(range), result);
}

/**
 * Convenience helper for copying elements of @p range for which predicate @p p
 * returns @c true.
 * Use std::ranges::copy_if() instead if you can use C++20.
 */
template<typename InputRange, typename OutputIterator, typename UnaryPredicate>
OutputIterator copy_if(InputRange &&range, OutputIterator result, UnaryPredicate p)
{
    return std::copy_if(std::begin(range), std::end(range), result, p);
}

/**
 * Convenience helper for transforming the elements of @p range.
 * Use std::ranges::transform() instead if you can use C++20.
 */
template<typename InputRange, typename OutputIterator, typename UnaryOperation>
OutputIterator transform(InputRange &&range, OutputIterator result, UnaryOperation op)
{
    return std::transform(std::begin(range), std::end(range), result, op);
}

/**
 * Convenience helper for transforming the elements of @p range for which
 * predicate @p p return @c true.
 */
template<typename InputRange, typename OutputIterator, typename UnaryOperation, typename UnaryPredicate>
OutputIterator transform_if(InputRange &&range, OutputIterator result, UnaryOperation op, UnaryPredicate p)
{
    auto first = std::begin(range);
    auto last = std::end(range);
    for (auto first = std::begin(range), last = std::end(range); first != last; ++first, (void)++result) {
        if (std::invoke(p, *first)) {
            *result = std::invoke(op, *first);
        }
    }
    return std::move(result);
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
