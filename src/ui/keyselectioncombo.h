/*  This file is part of Kleopatra, the KDE keymanager
    Copyright (c) 2016 Klarälvdalens Datakonsult AB

    Kleopatra is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kleopatra is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef KLEO_KEYSELECTIONCOMBO_H
#define KLEO_KEYSELECTIONCOMBO_H

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
    virtual ~KeySelectionCombo();

    void setKeyFilter(const std::shared_ptr<const KeyFilter> &kf);
    std::shared_ptr<const KeyFilter> keyFilter() const;

    void setIdFilter(const QString &id);
    QString idFilter() const;

    void refreshKeys();

    GpgME::Key currentKey() const;
    void setCurrentKey(const GpgME::Key &key);
    void setCurrentKey(const QString &fingerprint);

    void setDefaultKey(const QString &fingerprint);
    QString defaultKey() const;

    void prependCustomItem(const QIcon &icon, const QString &text, const QVariant &data);
    void appendCustomItem(const QIcon &icon, const QString &text, const QVariant &data);

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
#endif
