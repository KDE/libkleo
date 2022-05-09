/* -*- mode: c++; c-basic-offset:4 -*-
    checksumdefinition.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QString>
#include <QStringList>

#include <memory>
#include <vector>

class QProcess;

namespace Kleo
{

class KLEO_EXPORT ChecksumDefinition
{
protected:
    ChecksumDefinition(const QString &id, const QString &label, const QString &outputFileName, const QStringList &extensions);

public:
    using Ptr = std::shared_ptr<ChecksumDefinition>;

    virtual ~ChecksumDefinition();

    enum ArgumentPassingMethod {
        CommandLine,
        NewlineSeparatedInputFile,
        NullSeparatedInputFile,

        NumArgumentPassingMethods
    };

    QString id() const
    {
        return m_id;
    }
    QString label() const
    {
        return m_label;
    }

    const QStringList &patterns() const
    {
        return m_patterns;
    }
    QString outputFileName() const
    {
        return m_outputFileName;
    }

    QString createCommand() const;
    ArgumentPassingMethod createCommandArgumentPassingMethod() const
    {
        return m_createMethod;
    }

    QString verifyCommand() const;
    ArgumentPassingMethod verifyCommandArgumentPassingMethod() const
    {
        return m_verifyMethod;
    }

    bool startCreateCommand(QProcess *process, const QStringList &files) const;
    bool startVerifyCommand(QProcess *process, const QStringList &files) const;

    static QString installPath();
    static void setInstallPath(const QString &ip);

    static std::vector<Ptr> getChecksumDefinitions();
    static std::vector<Ptr> getChecksumDefinitions(QStringList &errors);

    static Ptr getDefaultChecksumDefinition(const std::vector<Ptr> &available);
    static void setDefaultChecksumDefinition(const Ptr &checksumDefinition);

protected:
    void setCreateCommandArgumentPassingMethod(ArgumentPassingMethod method)
    {
        m_createMethod = method;
    }
    void setVerifyCommandArgumentPassingMethod(ArgumentPassingMethod method)
    {
        m_verifyMethod = method;
    }

private:
    virtual QString doGetCreateCommand() const = 0;
    virtual QString doGetVerifyCommand() const = 0;
    virtual QStringList doGetCreateArguments(const QStringList &files) const = 0;
    virtual QStringList doGetVerifyArguments(const QStringList &files) const = 0;

private:
    const QString m_id;
    const QString m_label;
    const QString m_outputFileName;
    const QStringList m_patterns;
    ArgumentPassingMethod m_createMethod = CommandLine;
    ArgumentPassingMethod m_verifyMethod = CommandLine;
};

}
