/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QValidator>

#include <memory>
#include <vector>

namespace Kleo
{

class MultiValidator : public QValidator
{
    Q_OBJECT

    explicit MultiValidator(const std::vector<std::shared_ptr<QValidator>> &validators);

public:
    /**
     * Creates a combined validator from the \p validators.
     *
     * The validators must not be null and they must not have a parent.
     */
    static std::shared_ptr<QValidator> create(const std::vector<std::shared_ptr<QValidator>> &validators);

    ~MultiValidator() override;

    void fixup(QString &str) const override;
    State validate(QString &str, int &pos) const override;

private:
    std::vector<std::shared_ptr<QValidator>> m_validators;
};

}
