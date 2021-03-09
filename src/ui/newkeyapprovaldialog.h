/*  -*- c++ -*-
    newkeyapprovaldialog.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2018 Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
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
 * Resolved recipients in this API means a recipient could be resolved
 * to a single useful key. An unresolved recipient is a recipient for
 * whom no key could be found. Import / Search will be offered for such
 * a recipient. Multiple keys for signing / recipient can come e.g. from
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
     * @param resolvedSigningKeys: A map of signing addresses and Keys. Usually the
     *                             map would contain a single element and a single key
     *                             but configuration may allow more.
     * @param resolvedRecp: A map of a recipient address and the keys for that address. Multiple
     *                      keys could for example be configured through Address book or GnuPG
     *                      Groups.
     * @param unresolvedSigKeys: A list of signing addresses for which no key was found. Should
     *                           usually be only one. If resolved and unresolved sig keys are
     *                           empty it is assumed signing was not selected.
     * @param unresolvedRecp: A list of encryption target addresses if both unresolved and
     *                        resolved recipients are empty it is assumed no encryption should
     *                        take place.
     * @param senderAddr: The address of the sender, this may be used if singing is not
     *                    specified to identify a recipient for which "Generate Key" should
     *                    be offered.
     * @param allowMixed: Whether or not the dialog should allow mixed CMS / PGP key selection.
     * @param forcedProtocol: A specific forced protocol.
     * @param presetProtocol: A specific preselected protocol. If Protocol is unknown it will allow
     *               both (depending on allowMixed) S/MIME and OpenPGP.
     * @param parent: The parent widget.
     * @param f: The Qt window flags.
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

    ~NewKeyApprovalDialog() override;

    /** @brief The selected signing Keys. Only valid after Dialog was accepted. */
    std::vector<GpgME::Key> signingKeys();
    /** @brief The selected encryption Keys. Only valid after Dialog was accepted. */
    QMap<QString, std::vector<GpgME::Key> > encryptionKeys();

private:
    class Private;
    std::unique_ptr<Private> d;
};

} // namespace kleo

#endif //__KLEO_NEWKEYAPPROVALDIALOG_H__
