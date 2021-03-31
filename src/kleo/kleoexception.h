/* -*- mode: c++; c-basic-offset:4 -*-
    exception.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <gpg-error.h>
#include <gpgme++/exception.h>

#include <QString>

namespace Kleo
{

class KLEO_EXPORT Exception : public GpgME::Exception
{
public:
    Exception(gpg_error_t e, const std::string &msg, Options opt = NoOptions)
        : GpgME::Exception(GpgME::Error(e), msg, opt) {}
    Exception(gpg_error_t e, const char *msg, Options opt = NoOptions)
        : GpgME::Exception(GpgME::Error(e), msg, opt) {}
    Exception(gpg_error_t e, const QString &msg, Options opt = NoOptions)
        : GpgME::Exception(GpgME::Error(e), msg.toLocal8Bit().constData(), opt) {}

    Exception(const GpgME::Error &e, const std::string &msg)
        : GpgME::Exception(e, msg) {}
    Exception(const GpgME::Error &e, const char *msg)
        : GpgME::Exception(e, msg) {}
    Exception(const GpgME::Error &e, const QString &msg)
        : GpgME::Exception(e, msg.toLocal8Bit().constData()) {}

    ~Exception() throw ();

    const std::string &messageLocal8Bit() const
    {
        return GpgME::Exception::message();
    }
    gpg_error_t error_code() const
    {
        return error().encodedError();
    }

    QString message() const
    {
        return QString::fromLocal8Bit(GpgME::Exception::message().c_str());
    }
};

}

