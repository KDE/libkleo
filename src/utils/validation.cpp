/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "validation.h"

#include "multivalidator_p.h"
#include <libkleo_debug.h>

#include <QValidator>

#include <KEmailAddress>

#include <QRegularExpression>

using namespace Kleo;

namespace
{

template<class Validator>
class TrimmingValidator : public Validator
{
public:
    using Validator::Validator;

    QValidator::State validate(QString &str, int &pos) const override
    {
        auto trimmed = str.trimmed();
        auto posCopy = pos;
        return Validator::validate(trimmed, posCopy);
    }
};

template<class Validator>
class EmptyIsAcceptableValidator : public Validator
{
public:
    using Validator::Validator;

    QValidator::State validate(QString &str, int &pos) const override
    {
        if (str.isEmpty()) {
            return QValidator::Acceptable;
        }
        return Validator::validate(str, pos);
    }
};

class EMailValidator : public QValidator
{
public:
    EMailValidator()
        : QValidator{}
    {
    }

    State validate(QString &str, int &pos) const override
    {
        Q_UNUSED(pos)
        if (KEmailAddress::isValidSimpleAddress(str)) {
            return Acceptable;
        }
        return Intermediate;
    }
};

std::shared_ptr<QValidator> regularExpressionValidator(Validation::Flags flags, const QString &regexp)
{
    if (flags & Validation::Required) {
        return std::make_shared<TrimmingValidator<QRegularExpressionValidator>>(QRegularExpression{regexp});
    } else {
        return std::make_shared<TrimmingValidator<EmptyIsAcceptableValidator<QRegularExpressionValidator>>>(QRegularExpression{regexp});
    }
}

}

std::shared_ptr<QValidator> Validation::email(Flags flags)
{
    if (flags & Required) {
        return std::make_shared<TrimmingValidator<EMailValidator>>();
    } else {
        return std::make_shared<TrimmingValidator<EmptyIsAcceptableValidator<EMailValidator>>>();
    }
}

std::shared_ptr<QValidator> Validation::email(const QString &addRX, Flags flags)
{
    return MultiValidator::create({email(flags), regularExpressionValidator(flags, addRX)});
}

std::shared_ptr<QValidator> Validation::pgpName(Flags flags)
{
    // this regular expression is modeled after gnupg/g10/keygen.c:ask_user_id:
    static const QString name_rx{QLatin1StringView{"[^0-9<>][^<>@]{4,}"}};
    return regularExpressionValidator(flags, name_rx);
}

std::shared_ptr<QValidator> Validation::pgpName(const QString &addRX, Flags flags)
{
    return MultiValidator::create({pgpName(flags), regularExpressionValidator(flags, addRX)});
}

std::shared_ptr<QValidator> Validation::simpleName(Flags flags)
{
    static const QString name_rx{QLatin1StringView{"[^<>@]*"}};
    return std::shared_ptr<QValidator>{regularExpressionValidator(flags, name_rx)};
}

std::shared_ptr<QValidator> Validation::simpleName(const QString &additionalRegExp, Flags flags)
{
    return MultiValidator::create({simpleName(flags), regularExpressionValidator(flags, additionalRegExp)});
}
