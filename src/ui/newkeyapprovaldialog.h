/*  -*- c++ -*-
    newkeyapprovaldialog.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2018 Intevation GmbH
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <Libkleo/KeyResolver>

#include <QDialog>

#include <memory>

#include "kleo_export.h"

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
     * @param sender: The address of the sender, this may be used if signing is not
     *                specified to identify a recipient for which "Generate Key" should
     *                be offered.
     * @param preferredSolution: The preferred signing and/or encryption keys for the sender
     *                           and the recipients.
     * @param alternativeSolution: An alternative set of signing and/or encryption keys for the sender
     *                             and the recipients. Typically, S/MIME-only, if preferred solution is OpenPGP-only,
     *                             and vice versa. Ignored, if mixed protocol selection is allowed.
     * @param allowMixed: Whether or not the dialog should allow mixed S/MIME / OpenPGP key selection.
     * @param forcedProtocol: A specific forced protocol.
     * @param parent: The parent widget.
     * @param f: The Qt window flags.
     */
    explicit NewKeyApprovalDialog(bool encrypt,
                                  bool sign,
                                  const QString &sender,
                                  KeyResolver::Solution preferredSolution,
                                  KeyResolver::Solution alternativeSolution,
                                  bool allowMixed,
                                  GpgME::Protocol forcedProtocol,
                                  QWidget *parent = nullptr,
                                  Qt::WindowFlags f = Qt::WindowFlags());

    ~NewKeyApprovalDialog() override;

    /** @brief The selected signing and/or encryption keys. Only valid after the dialog was accepted. */
    KeyResolver::Solution result();

private:
    class Private;
    std::unique_ptr<Private> d;
};

} // namespace kleo

