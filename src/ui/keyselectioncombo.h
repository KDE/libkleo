/*  This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <libkleo/enum.h>
#include <libkleo/keyusage.h>

#include <QComboBox>

#include <gpgme++/global.h>

#include <memory>

namespace GpgME
{
class Key;
}

namespace Kleo
{
class KeyFilter;
class KeySelectionComboPrivate;

class KLEO_EXPORT KeySelectionCombo : public QComboBox
{
    Q_OBJECT

public:
    explicit KeySelectionCombo(QWidget *parent = nullptr);
    explicit KeySelectionCombo(bool secretOnly, QWidget *parent = nullptr);
    /**
     * @param usage the desired usage of the certificate
     *
     * \a usage is used to mark certificates that cannot be used for the desired
     * usage with an appropriate icon. This is useful in combination with a suitable
     * key filter.
     * For example, the key filter could filter out any certificates without
     * encryption subkeys and the usage flags would mark certificates with expired
     * encryption subkeys as unusable, so that the users see that there is a
     * certificate, but that it cannot be used.
     */
    explicit KeySelectionCombo(bool secretOnly, KeyUsage::Flags usage, QWidget *parent = nullptr);
    ~KeySelectionCombo() override;

    void setKeyFilter(const std::shared_ptr<const KeyFilter> &kf);
    std::shared_ptr<const KeyFilter> keyFilter() const;

    void setIdFilter(const QString &id);
    QString idFilter() const;

    void refreshKeys();

    GpgME::Key currentKey() const;
    void setCurrentKey(const GpgME::Key &key);
    void setCurrentKey(const QString &fingerprint);

    void setDefaultKey(const QString &fingerprint);
    void setDefaultKey(const QString &fingerprint, GpgME::Protocol proto);
    QString defaultKey() const;
    QString defaultKey(GpgME::Protocol proto) const;

    void prependCustomItem(const QIcon &icon, const QString &text, const QVariant &data);
    void appendCustomItem(const QIcon &icon, const QString &text, const QVariant &data);
    void prependCustomItem(const QIcon &icon, const QString &text, const QVariant &data, const QString &toolTip);
    void appendCustomItem(const QIcon &icon, const QString &text, const QVariant &data, const QString &toolTip);
    void removeCustomItem(const QVariant &data);

Q_SIGNALS:
    void customItemSelected(const QVariant &data);
    void currentKeyChanged(const GpgME::Key &key);
    void keyListingFinished();

protected:
    virtual void init();

private:
    std::unique_ptr<KeySelectionComboPrivate> const d;
};

}
