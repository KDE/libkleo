/*  -*- c++ -*-
    keyresolver.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2018 Intevation GmbH
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QMap>
#include <QObject>
#include <QString>

#include <gpgme++/global.h>

#include <memory>
#include <vector>

#include "kleo_export.h"

class QStringList;

namespace GpgME
{
class Key;
}

namespace Kleo
{
/**
 * Class to find Keys for E-Mail signing and encryption.
 *
 * The KeyResolver uses the Keycache to find keys for signing
 * or encryption.
 *
 * Overrides can be provided for address book integration.
 *
 * If no override key(s) are provided for an address and no
 * KeyGroup for this address is found, then the key
 * with a uid that matches the address and has the highest
 * validity is used. If both keys have the same validity,
 * then the key with the newest subkey is used.
 *
 * The KeyResolver also supports groups so the number of
 * encryption keys does not necessarily
 * need to match the amount of sender addresses. For this reason
 * maps are used to map addresses to lists of keys.
 *
 * The keys can be OpenPGP keys and S/MIME (CMS) keys.
 * As a caller you need to partition the keys by their protocol and
 * send one message for each protocol for the recipients and signed
 * by the signing keys.
 */
class KLEO_EXPORT KeyResolver : public QObject
{
    Q_OBJECT

public:
    /**
     * Solution represents the solution found by the KeyResolver.
     * @a protocol hints at the protocol of the signing and encryption keys,
     * i.e. if @a protocol is either @c GpgME::OpenPGP or @c GpgME::CMS, then
     * all keys have the corresponding protocol. Otherwise, the keys have
     * mixed protocols.
     * @a signingKeys contains the signing keys to use. It contains
     * zero or one OpenPGP key and zero or one S/MIME key.
     * @a encryptionKeys contains the encryption keys to use for the
     * different recipients. The keys of the map represent the normalized
     * email addresses of the recipients.
     */
    struct Solution
    {
        GpgME::Protocol protocol = GpgME::UnknownProtocol;
        std::vector<GpgME::Key> signingKeys;
        QMap<QString, std::vector<GpgME::Key>> encryptionKeys;
    };

    /** Creates a new key resolver object.
     *
     * @param encrypt: Should encryption keys be selected.
     * @param sign: Should signing keys be selected.
     * @param protocol: A specific key protocol (OpenPGP, S/MIME) for selection. Default: Both protocols.
     * @param allowMixed: Specify if multiple message formats may be resolved.
     **/
    explicit KeyResolver(bool encrypt, bool sign,
                         GpgME::Protocol protocol = GpgME::UnknownProtocol,
                         bool allowMixed = true);

    ~KeyResolver() override;

    /**
     *  Set the list of recipient addresses.
     *
     *  @param addresses: A list of (not necessarily normalized) email addresses
    */
    void setRecipients(const QStringList &addresses);

    /**
     * Set the sender's address.
     *
     * This address is added to the list of recipients (for encryption to self)
     * and it is used for signing key resolution, if the signing keys are not
     * explicitly set through setSigningKeys.
     *
     * @param sender: The sender of this message.
     */
    void setSender(const QString &sender);

    /**
     * Set up possible override keys for recipients addresses.
     * The keys for the fingerprints are looked
     * up and used when found.
     *
     * Overrides for @c GpgME::UnknownProtocol are used regardless of the
     * protocol. Overrides for a specific protocol are only used for this
     * protocol. Overrides for @c GpgME::UnknownProtocol takes precendent over
     * overrides for a specific protocol.
     *
     * @param overrides: A map of \<protocol\> -> (\<address\> \<fingerprints\>)
    */
    void setOverrideKeys(const QMap<GpgME::Protocol, QMap<QString, QStringList> > &overrides);

    /**
     * Set explicit signing keys to use.
     */
    void setSigningKeys(const QStringList &fingerprints);

    /**
     * Set the minimum user id validity for autoresolution.
     *
     * The default value is marginal
     *
     * @param validity int representation of a GpgME::UserID::Validity.
     */
    void setMinimumValidity(int validity);

    /**
     * Get the result of the resolution.
     *
     * @return the resolved keys for signing and encryption.
     */
    Solution result() const;

    /**
     * Starts the key resolving procedure. Emits keysResolved on success or
     * error.
     *
     * @param showApproval: If set to true a dialog listing the keys
     *                      will always be shown.
     * @param parentWidget: Optional, a Widget to use as parent for dialogs.
     */
    void start(bool showApproval, QWidget *parentWidget = nullptr);

    /**
     * Set window flags for a possible dialog.
     */
    void setDialogWindowFlags(Qt::WindowFlags flags);

    /**
     * Set the protocol that is preferred to be displayed first when
     * it is not clear from the keys. E.g. if both OpenPGP and S/MIME
     * can be resolved.
     */
    void setPreferredProtocol(GpgME::Protocol proto);

Q_SIGNALS:
    /**
     * Emitted when key resolution finished.
     *
     * @param success: The general result. If true continue sending,
     *                 if false abort.
     * @param sendUnencrypted: If there could be no key found for one of
     *                         the recipients the user was queried if the
     *                         mail should be sent out unencrypted.
     *                         sendUnencrypted is true if the user agreed
     *                         to this.*/
    void keysResolved(bool success, bool sendUnencrypted);

private:
    class Private;
    std::unique_ptr<Private> d;
};
} // namespace Kleo
