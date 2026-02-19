/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QFlags>

namespace Kleo
{

class KLEO_EXPORT KeyUsage
{
public:
    enum Flag {
        None = 0,
        Certify = 1,
        Sign = 2,
        Encrypt = 4,
        Authenticate = 8,
        Group = 16,
    };
    Q_DECLARE_FLAGS(Flags, Flag)

    KeyUsage()
    {
    }

    explicit KeyUsage(Flags flags)
        : mFlags{flags}
    {
    }

    void setValue(Flags flags)
    {
        mFlags = flags;
    }
    Flags value() const
    {
        return mFlags;
    }

    void setCanAuthenticate(bool set)
    {
        mFlags.setFlag(Authenticate, set);
    }
    bool canAuthenticate() const
    {
        return mFlags.testFlag(Authenticate);
    }

    void setCanCertify(bool set)
    {
        mFlags.setFlag(Certify, set);
    }
    bool canCertify() const
    {
        return mFlags.testFlag(Certify);
    }

    void setCanEncrypt(bool set)
    {
        mFlags.setFlag(Encrypt, set);
    }
    bool canEncrypt() const
    {
        return mFlags.testFlag(Encrypt);
    }

    void setCanSign(bool set)
    {
        mFlags.setFlag(Sign, set);
    }
    bool canSign() const
    {
        return mFlags.testFlag(Sign);
    }

    void setIsGroupKey(bool isGroupKey)
    {
        mFlags.setFlag(Group, isGroupKey);
    }
    bool isGroupKey() const
    {
        return mFlags.testFlag(Group);
    }

private:
    Flags mFlags;
};

Q_DECLARE_OPERATORS_FOR_FLAGS(KeyUsage::Flags)

}
