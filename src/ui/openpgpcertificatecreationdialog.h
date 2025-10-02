/* -*- mode: c++; c-basic-offset:4 -*-
    ui/newopenpgpcertificatedialog.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QDialog>

#include <memory>

namespace Kleo
{
class KeyParameters;

/**
 * Dialog to create a new OpenPGP key
 */
class KLEO_EXPORT OpenPGPCertificateCreationDialog : public QDialog
{
    Q_OBJECT

public:
    explicit OpenPGPCertificateCreationDialog(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~OpenPGPCertificateCreationDialog() override;

    void setName(const QString &name);
    QString name() const;

    void setEmail(const QString &email);
    QString email() const;

    void setNameLabel(const QString &nameLabel);
    void setEmailLabel(const QString &emailLabel);

    void setKeyParameters(const KeyParameters &parameters);
    KeyParameters keyParameters() const;

    void setProtectKeyWithPassword(bool protectKey);
    bool protectKeyWithPassword() const;

    void setInfoText(const QString &text);

    bool isTeamKey() const;
    void showTeamKeyOption(bool show);

private:
    class Private;
    const std::unique_ptr<Private> d;
};

} // namespace Kleo
