/*  This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QGpgME/Job>

#include <memory>

namespace GpgME
{
class KeyGenerationResult;
}

namespace Kleo
{

/**
 * Generates a PGP RSA/2048 bit key pair for given name and email address.
 *
 * @since 5.4
 *
 * This class is deprecated. GnuPG defaults to ECC keys and RSA 2048 is no
 * longer allowed by some entities. Use QuickJob::startCreate from QGpgME
 * instead.
 */
class KLEO_DEPRECATED_EXPORT DefaultKeyGenerationJob : public QGpgME::Job
{
    Q_OBJECT
public:
    explicit DefaultKeyGenerationJob(QObject *parent = nullptr);
    ~DefaultKeyGenerationJob() override;

    /**
     * Set key passphrase
     *
     * Use this method to specify custom passphrase, including an empty
     * one. If no passphrase (not even empty) is specified, gpg me will
     * automatically prompt for passphrase using Pinentry dialog.
     */
    void setPassphrase(const QString &passphrase);

    GpgME::Error start(const QString &email, const QString &name);

    QString auditLogAsHtml() const override;
    GpgME::Error auditLogError() const override;

public Q_SLOTS:
    void slotCancel() override;

Q_SIGNALS:
    void result(const GpgME::KeyGenerationResult &result, const QByteArray &pubkeyData, const QString &auditLogAsHtml, const GpgME::Error &auditLogError);

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    class DefaultKeyGenerationJobPrivate;
    std::unique_ptr<DefaultKeyGenerationJobPrivate> const d;
};

}
