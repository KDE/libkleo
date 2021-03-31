/*  -*- c++ -*-
    keyapprovaldialog.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    Based on kpgpui.h
    SPDX-FileCopyrightText: 2001, 2002 the KPGP authors
    See file libkdenetwork/AUTHORS.kpgp for details

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"
#include "libkleo/enum.h"

#include <QDialog>

#include <gpgme++/key.h>

#include <vector>

namespace GpgME
{
class Key;
}

namespace Kleo
{

class KLEO_EXPORT KeyApprovalDialog : public QDialog
{
    Q_OBJECT
public:
    struct Item {
        Item() : pref(UnknownPreference) {}
        Item(const QString &a, const std::vector<GpgME::Key> &k,
             EncryptionPreference p = UnknownPreference)
            : address(a), keys(k), pref(p) {}
        QString address;
        std::vector<GpgME::Key> keys;
        EncryptionPreference pref;
    };

    KeyApprovalDialog(const std::vector<Item> &recipients,
                      const std::vector<GpgME::Key> &sender,
                      QWidget *parent = nullptr);
    ~KeyApprovalDialog();

    std::vector<Item> items() const;
    std::vector<GpgME::Key> senderKeys() const;

    bool preferencesChanged() const;

private Q_SLOTS:
    void slotPrefsChanged();

private:
    class Private;
    Private *const d;
};

} // namespace Kleo

