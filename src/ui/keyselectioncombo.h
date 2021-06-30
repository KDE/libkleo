/*  This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QComboBox>

#include <gpgme++/global.h>

#include <kleo_export.h>
#include <libkleo/enum.h>

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
    KeySelectionComboPrivate * const d;
};

}
