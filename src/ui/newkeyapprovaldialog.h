/*  -*- c++ -*-
    newkeyapprovaldialog.h

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
#ifndef __KLEO_NEWKEYAPPROVALDIALOG_H__
#define __KLEO_NEWKEYAPPROVALDIALOG_H__

#include "kleo_export.h"

#include <QDialog>

#include <gpgme++/key.h>

#include <vector>

namespace Kleo
{

/** @brief A dialog to show for encryption / signing key approval or selection.
 *
 * This class is intended to replace the old KeyApprovalDialog with a new
 * and simpler interface.
 *
 * Resolved recipients in this API means a recpient could be resolved
 * to a single useful key. An unresolved recipient is a recpient for
 * whom no key could be found. Import / Search will be offered for such
 * a recpient. Multiple keys for signing / recpient can come e.g. from
 * group configuration or Addressbook / Identity configuration.
 *
 * The Dialog uses the Level System for validity display and shows an
 * overall outgoing level.
 *
 */
class KLEO_EXPORT NewKeyApprovalDialog : public QDialog
{
    Q_OBJECT
public:
    /** @brief Create a new Key Approval Dialog.
     *
     * @param resolvedSignignKeys: A map of signing addresses and Keys. Usually the
     *                             map would contain a single element and a single key
     *                             but configuration may allow more.
     * @param resolvedRecp: A map of a recpient address and the keys for that address. Multiple
     *                      keys could for example be configured through Address book or GnuPG
     *                      Groups.
     * @param unresolvedSigKeys: A list of signing addresses for which no key was found. Should
     *                           usually be only one. If resolved and unresovled sig keys are
     *                           empty it is assumed signing was not selected.
     * @param unresolvedRecp: A list of encryption target addresses if both unresolved and
     *                        resolved recipients are empty it is assumed no encryption should
     *                        take place.
     * @param senderAddr: The address of the sender, this may be used if singing is not
     *                    specified to identify a recpient for which "Generate Key" should
     *                    be offered.
     * @param allowMixed: Whether or not the dialog should allow mixed CMS / PGP key selection.
     * @param proto: A specific preselected protocol. If Protocol is unknown it will allow
     *               both (depending on allowMixed) S/MIME and OpenPGP.
     * @param parent: The parent widget.
     */
    explicit NewKeyApprovalDialog(const QMap<QString, std::vector<GpgME::Key> > &resolvedSigningKeys,
                                  const QMap<QString, std::vector<GpgME::Key> > &resolvedRecp,
                                  const QStringList &unresolvedSigKeys,
                                  const QStringList &unresolvedRecp,
                                  const QString &senderAddr,
                                  bool allowMixed,
                                  GpgME::Protocol forcedProtocol,
                                  GpgME::Protocol presetProtocol,
                                  QWidget *parent = nullptr,
                                  Qt::WindowFlags f = Qt::WindowFlags());

    /** @brief The selected signing Keys. Only valid after Dialog was accepted. */
    std::vector<GpgME::Key> signingKeys();
    /** @brief The selected encryption Keys. Only valid after Dialog was accepted. */
    QMap<QString, std::vector<GpgME::Key> > encryptionKeys();

private:
    class Private;
    std::shared_ptr<Private> d;
};

} // namespace kleo

#endif //__KLEO_NEWKEYAPPROVALDIALOG_H__
