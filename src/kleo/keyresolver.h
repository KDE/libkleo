/*  -*- c++ -*-
    keyresolver.h

    This file is part of libkleopatra, the KDE keymanagement library
    Copyright (c) 2018 Intevation GmbH

    Libkleopatra is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    Libkleopatra is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    In addition, as a special exception, the copyright holders give
    permission to link the code of this program with any edition of
    the Qt library by Trolltech AS, Norway (or with modified versions
    of Qt that use the same license as Qt), and distribute linked
    combinations including the two.  You must obey the GNU General
    Public License in all respects for all of the code used other than
    Qt.  If you modify this file, you may extend this exception to
    your version of the file, but you are not obligated to do so.  If
    you do not wish to do so, delete this exception statement from
    your version.
*/

#ifndef __KLEO_KEYRESOLVER_H__
#define __KLEO_KEYRESOLVER_H__

#include "kleo_export.h"
#include <Libkleo/Enum>

#include <gpgme++/key.h>

#include <vector>
#include <QMap>
#include <QString>
#include <QObject>

#include <memory>

class QStringList;

namespace Kleo
{
/**
 * Class to find Keys for E-Mail encryption.
 *
 * The KeyResolver uses the Keycache to find keys for signing
 * or encryption.
 *
 * Overrides can be provided for address book integration if the
 * format is not Auto overrides will only be respected if they
 * match the format provided in the constructor.
 *
 * If no override key is provided for an address the key
 * with a uid that maches the address and has the highest
 * validity is used. If both keys have the same validity
 * the newest subkey is used.
 *
 * The KeyResolver also supports groups so the number of
 * encryption keys / hidden encryption keys does not necessarily
 * need to match the amount of sender addresses. For this reason
 * maps are used heavily to map:
 *
 * CryptoFormat
 *   - Addresses
 *   -- For each Address a List of Keys
 *
 * As a caller you should iterate over the CryptoFormats and
 * send one message for each format for the recipients and signed
 * by the signing keys.
 *
 * If the CryptoMessageFormat is Auto the minmum number
 * of CryptoMessageFormats is returned that respects all overrides.
 *
 * -----
 * Planned:
 *
 * As the central place to manage mail encryption / signing keys
 * the Keyresolver will also show various warning / nagging messages
 * and offer solutions if nagging is not explicitly turned off.
 * These include:
 *
 * - If own keys or subkeys are about to expire:
 *   Offer to extend their expiration date.
 *
 * - (S/MIME) If they are about to expire: Offer
 *   to generate a new CSR.
 *
 * - If a user has not marked a key as backed up and
 *   uses it for encryption for several mails.
 *
 * - If a user has multiple keys for a sender address and they
 *   are not cross signed. Offer to cross sign / publish.
 */
class KLEO_EXPORT KeyResolver : public QObject
{
    Q_OBJECT

public:
    /** Creates a new key resolver object.
     *
     * @param encrypt: Should encryption keys be selected.
     * @param sign: Should signing keys be selected.
     * @param format: A specific format for selection. Default Auto.
     * @param allowMixed: Specify if multiple message formats may be resolved.
     **/
    explicit KeyResolver(bool encrypt, bool sign,
                         CryptoMessageFormat format = AutoFormat,
                         bool allowMixed = true);
    ~KeyResolver() {}

    /**
     *  Set the list of (To/CC) recipient addresses. Also looks
     *  up possible keys, but doesn't interact with the user.
     *
     *  @param addresses: A list of unnormalized addresses
    */
    void setRecipients(const QStringList &addresses);

    /**
     * Set the senders address.
     *
     * Sender address will be added to encryption keys and used
     * for signing key resolution if the signing keys are not
     * explicitly set through setSigningKeys.
     *
     * @param sender: The sender of this message.
     */
    void setSender(const QString &sender);

    /**
     *  Set the list of hidden (BCC) recipient addresses. Also looks
     *  up possible keys, but doesn't interact with the user.
     *
     *  @param addresses: A list of unnormalized addresses.
    */
    void setHiddenRecipients(const QStringList &addresses);

    /**
     * Set up possible override keys for recpients / sender
     * addresses. The keys for the fingerprints are looked
     * up and used when found. Does not interact with the user.
     *
     * @param overrides: A map of <cryptomessageformat> -> (<address> <fingerprints>)
    */
    void setOverrideKeys(const QMap<CryptoMessageFormat, QMap<QString, QStringList> > &overrides);

    /**
     * Set explicit signing keys. If this was set for a
     * protocol the sender address will be only used as an additional encryption
     * recipient for that protocol. */
    void setSigningKeys(const QStringList &fingerprints);

    /**
     * Turn Nagging messages off or on, default on.
     * See class description about nagging.
     *
     * @param value: Turn nagging on or off.
     */
    void enableNagging(bool value);

    /**
     * Set the minimum user id validity for autoresolution.
     *
     * The default value is marginal
     *
     * @param value: int representation of a GpgME::UserID::Validity.
     */
    void setMinimumValidity(int validity);

    /**
     * Get the encryption keys after resolution.
     *
     * @return the resolved sender / key pairs for encryption by format.
     */
    QMap <CryptoMessageFormat, QMap<QString, std::vector<GpgME::Key> > > encryptionKeys() const;

    /**
     * Get the secondary encryption keys after resolution.
     * The Map will only contain values if hidden recipients
     * were set.
     *
     * @return the resolved resolved sender / key pairs for encryption
     *         by format.
     */
    QMap <CryptoMessageFormat, QMap<QString, std::vector<GpgME::Key> > > hiddenKeys() const;

    /**
     * Get the signing keys to use after resolution.
     *
     * @return the resolved resolved sender / key pairs for signing
     *         by format.
     */
    QMap <CryptoMessageFormat, std::vector<GpgME::Key> > signingKeys() const;

    /**
     * Starts the key resolving proceure. Emits keysResolved on success or
     * error.
     *
     * @param showApproval: If set to true a dialog listing the keys
     *                      will always be shown.
     * @param parentWidget: Optional, a Widget to use as parent for dialogs.
     */
    void start(bool showApproval, QWidget *parentWidget = nullptr);

    /**
     * Access possibly updated Override Keys
     *
     * @return A map of email's with new overrides and the according
     *         cryptoformat / fingerprint. Should be saved somehow.
     */
    QMap <CryptoMessageFormat, QMap<QString, QStringList> > overrideKeys() const;

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
    friend class Private;
    std::shared_ptr<Private> d;
};
} // namespace Kleo

#endif // __KLEO_KEYRESOLVER_H__

