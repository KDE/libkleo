/* -*- mode: c++; c-basic-offset:4 -*-
    utils/multivalidator.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "multivalidator_p.h"

#include <algorithm>
#include <iterator>

using namespace Kleo;

MultiValidator::MultiValidator(const std::vector<std::shared_ptr<QValidator>> &validators)
    : QValidator{}
    , m_validators{validators}
{
}

// static
std::shared_ptr<QValidator> Kleo::MultiValidator::create(const std::vector<std::shared_ptr<QValidator>> &validators)
{
    Q_ASSERT(std::all_of(std::begin(validators), std::end(validators), [](const auto &v) {
        return v && !v->parent();
    }));

    return std::shared_ptr<MultiValidator>{new MultiValidator{validators}};
}

MultiValidator::~MultiValidator() = default;

void MultiValidator::fixup(QString &str) const
{
    std::for_each(std::cbegin(m_validators), std::cend(m_validators), [&str](const auto &val) {
        val->fixup(str);
    });
}

QValidator::State MultiValidator::validate(QString &str, int &pos) const
{
    std::vector<State> states;
    states.reserve(m_validators.size());
    std::transform(std::cbegin(m_validators), std::cend(m_validators), std::back_inserter(states), [&str, &pos](const auto &val) {
        return val->validate(str, pos);
    });

    if (std::any_of(std::cbegin(states), std::cend(states), [](State state) {
            return state == Invalid;
        })) {
        return Invalid;
    }

    if (std::all_of(std::cbegin(states), std::cend(states), [](State state) {
            return state == Acceptable;
        })) {
        return Acceptable;
    }

    return Intermediate;
}

#include "moc_multivalidator_p.cpp"
