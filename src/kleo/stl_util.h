/****************************************************************************
** SPDX-FileCopyrightText: 2001-2007 Klarälvdalens Datakonsult AB. All rights reserved.
**
** This file is part of the KD Tools library.
**
** SPDX-License-Identifier: GPL-2.0-or-later
**
**********************************************************************/

#pragma once

#include <algorithm>
#include <numeric>
#include <utility>
#include <iterator>
#include <functional>

namespace kdtools
{
template<typename _Iterator, typename UnaryPredicate>
struct filter_iterator
{
    using value_type = typename std::iterator_traits<_Iterator>::value_type;
    using reference = typename std::iterator_traits<_Iterator>::reference;
    using pointer = typename std::iterator_traits<_Iterator>::pointer;
    using difference_type = typename std::iterator_traits<_Iterator>::difference_type;

    filter_iterator(UnaryPredicate pred, _Iterator it, _Iterator last) : it(it), last(last), pred(pred) {}
    template<typename _OtherIter>
    filter_iterator(const filter_iterator<_OtherIter, UnaryPredicate> &other) : it(other.it), last(other.last), pred(other.pred) {}
    filter_iterator &operator++() { while (++it != last && !pred(*it)){} return *this; }
    filter_iterator operator++(int) { auto retval = *this; while(++it != last && !pred(*it)){} return retval; }
    bool operator==(filter_iterator other) const { return it == other.it; }
    bool operator!=(filter_iterator other) const { return it != other.it; }
    typename _Iterator::reference operator*() const { return *it; }
private:
    _Iterator it, last;
    UnaryPredicate pred;
};

template<typename _Iterator, typename UnaryPredicate>
filter_iterator<typename std::decay<_Iterator>::type,
                UnaryPredicate>
make_filter_iterator(UnaryPredicate &&pred, _Iterator &&it, _Iterator &&last)
{
    return filter_iterator<typename std::decay<_Iterator>::type, 
                           UnaryPredicate>(
                std::forward<UnaryPredicate>(pred),
                std::forward<_Iterator>(it),
                std::forward<_Iterator>(last));
}

template <typename InputIterator, typename OutputIterator, typename UnaryPredicate>
OutputIterator copy_if(InputIterator first, InputIterator last, OutputIterator dest, UnaryPredicate pred)
{
    while (first != last) {
        if (pred(*first)) {
            *dest = *first;
            ++dest;
        }
        ++first;
    }
    return dest;
}

template <typename OutputIterator, typename InputIterator, typename UnaryFunction, typename UnaryPredicate>
void transform_if(InputIterator first, InputIterator last, OutputIterator dest, UnaryPredicate pred, UnaryFunction filter)
{
    for (; first != last; ++first) {
        if (filter(*first)) {
            *dest++ = pred(*first);
        }
    }
}

template <typename InputIterator, typename OutputIterator, typename Predicate>
OutputIterator copy_1st_if(InputIterator first, InputIterator last, OutputIterator dest, Predicate pred)
{
    const auto trans = [](typename std::iterator_traits<InputIterator>::reference v) {
                            return std::get<0>(v);
                       };
    kdtools::transform_if(first, last, dest, trans,
                          [&pred, &trans](typename std::iterator_traits<InputIterator>::reference v) {
                            return pred(trans(v));
                          });
    return dest;
}

template <typename InputIterator, typename OutputIterator, typename Predicate>
OutputIterator copy_2nd_if(InputIterator first, InputIterator last, OutputIterator dest, Predicate pred)
{
    const auto trans = [](typename std::iterator_traits<InputIterator>::reference v) {
                            return std::get<1>(v);
                       };
    kdtools::transform_if(first, last, dest, trans,
                          [&pred, &trans](typename std::iterator_traits<InputIterator>::reference v) {
                            return pred(trans(v));
                          });
    return dest;
}


template <typename OutputIterator, typename InputIterator, typename UnaryFunction>
OutputIterator transform_1st(InputIterator first, InputIterator last, OutputIterator dest, UnaryFunction func)
{
    return std::transform(first, last, dest,
                          [func](typename std::iterator_traits<InputIterator>::reference v) {
                              return func(std::get<0>(v));
                          });
}

template <typename OutputIterator, typename InputIterator, typename UnaryFunction>
OutputIterator transform_2nd(InputIterator first, InputIterator last, OutputIterator dest, UnaryFunction func)
{
    return std::transform(first, last, dest,
                          [func](typename std::iterator_traits<InputIterator>::reference v) {
                              return func(std::get<1>(v));
                          });
}

template <typename Value, typename InputIterator, typename UnaryPredicate>
Value accumulate_if(InputIterator first, InputIterator last, UnaryPredicate filter, const Value &value = Value())
{
    return std::accumulate(make_filter_iterator(filter, first, last),
                           make_filter_iterator(filter, last,  last), value);
}

template <typename Value, typename InputIterator, typename UnaryPredicate, typename BinaryOperation>
Value accumulate_if(InputIterator first, InputIterator last, UnaryPredicate filter, const Value &value, BinaryOperation op)
{
    return std::accumulate(make_filter_iterator(filter, first, last),
                           make_filter_iterator(filter, last,  last), value, op);
}

template <typename Value, typename InputIterator, typename UnaryFunction>
Value accumulate_transform(InputIterator first, InputIterator last, UnaryFunction map, const Value &value = Value())
{
    return std::accumulate(first, last, value,
                           [map](Value lhs,
                                 typename std::iterator_traits<InputIterator>::reference rhs)
                           {
                               return lhs + map(rhs);
                           });
}

template <typename Value, typename InputIterator, typename UnaryFunction, typename BinaryOperation>
Value accumulate_transform(InputIterator first, InputIterator last, UnaryFunction map, const Value &value, BinaryOperation op)
{
    return std::accumulate(first, last, value,
                           [map, op](typename InputIterator::reference lhs,
                                     typename InputIterator::reference rhs) {
                               return op(map(lhs), map(rhs));
                           });
}

template <typename Value, typename InputIterator, typename UnaryFunction, typename UnaryPredicate, typename BinaryOperation>
Value accumulate_transform_if(InputIterator first, InputIterator last, UnaryFunction map, UnaryPredicate filter, const Value &value, BinaryOperation op)
{
    return accumulate_transform(make_filter_iterator(filter, first, last),
                                make_filter_iterator(filter, last, last),
                                map, value, op);
}


template <typename InputIterator, typename BinaryOperation>
BinaryOperation for_each_adjacent_pair(InputIterator first, InputIterator last, BinaryOperation op)
{
    using ValueType = typename std::iterator_traits<InputIterator>::value_type;
    if (first == last) {
        return op;
    }
    ValueType value = *first;
    while (++first != last) {
        ValueType tmp = *first;
        op(value, tmp);
        value = tmp;
    }
    return op;
}


template <typename InputIterator, typename OutputIterator1, typename OutputIterator2, typename UnaryPredicate>
std::pair<OutputIterator1, OutputIterator2> separate_if(InputIterator first, InputIterator last, OutputIterator1 dest1, OutputIterator2 dest2, UnaryPredicate pred)
{
    while (first != last) {
        if (pred(*first)) {
            *dest1 = *first;
            ++dest1;
        } else {
            *dest2 = *first;
            ++dest2;
        }
        ++first;
    }
    return std::make_pair(dest1, dest2);
}

//@{
/**
   Versions of std::set_intersection optimized for ForwardIterator's
*/
template <typename ForwardIterator, typename ForwardIterator2, typename OutputIterator, typename BinaryPredicate>
OutputIterator set_intersection(ForwardIterator first1, ForwardIterator last1, ForwardIterator2 first2, ForwardIterator2 last2, OutputIterator result)
{
    while (first1 != last1 && first2 != last2) {
        if (*first1 < *first2) {
            first1 = std::lower_bound(++first1, last1, *first2);
        } else if (*first2 < *first1) {
            first2 = std::lower_bound(++first2, last2, *first1);
        } else {
            *result = *first1;
            ++first1;
            ++first2;
            ++result;
        }
    }
    return result;
}

template <typename ForwardIterator, typename ForwardIterator2, typename OutputIterator, typename BinaryPredicate>
OutputIterator set_intersection(ForwardIterator first1, ForwardIterator last1, ForwardIterator2 first2, ForwardIterator2 last2, OutputIterator result, BinaryPredicate pred)
{
    while (first1 != last1 && first2 != last2) {
        if (pred(*first1, *first2)) {
            first1 = std::lower_bound(++first1, last1, *first2, pred);
        } else if (pred(*first2, *first1)) {
            first2 = std::lower_bound(++first2, last2, *first1, pred);
        } else {
            *result = *first1;
            ++first1;
            ++first2;
            ++result;
        }
    }
    return result;
}
//@}

template <typename ForwardIterator, typename ForwardIterator2, typename BinaryPredicate>
bool set_intersects(ForwardIterator first1,  ForwardIterator last1,
                    ForwardIterator2 first2, ForwardIterator2 last2,
                    BinaryPredicate pred)
{
    while (first1 != last1 && first2 != last2) {
        if (pred(*first1, *first2)) {
            first1 = std::lower_bound(++first1, last1, *first2, pred);
        } else if (pred(*first2, *first1)) {
            first2 = std::lower_bound(++first2, last2, *first1, pred);
        } else {
            return true;
        }
    }
    return false;
}

}
