/*
    defaultkeyfilter.h

    This file is part of libkleopatra, the KDE keymanagement library
    Copyright (c) 2004 Klarälvdalens Datakonsult AB
    2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH

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

#ifndef __KLEO_DEFAULTKEYFILTER_H__
#define __KLEO_DEFAULTKEYFILTER_H__

#include "keyfilter.h"

#include "kleo_export.h"

#include <QFont>
#include <QString>
#include <QColor>
#include <QScopedPointer>

#include <gpgme++/key.h>

namespace Kleo
{

/** Default implemation of key filter class. */
class KLEO_EXPORT DefaultKeyFilter : public KeyFilter
{
public:
    DefaultKeyFilter();
    ~DefaultKeyFilter();

    /** Used for bool checks */
    enum TriState {
        DoesNotMatter = 0,
        Set = 1,
        NotSet = 2
    };

    /** Used for level checks */
    enum LevelState {
        LevelDoesNotMatter = 0,
        Is = 1,
        IsNot = 2,
        IsAtLeast = 3,
        IsAtMost = 4
    };

    bool matches(const GpgME::Key &key, MatchContexts ctx) const override;

    unsigned int specificity() const override;
    void setSpecificity(unsigned int value) const;
    QString id() const override;
    void setId(const QString &value) const;
    KeyFilter::MatchContexts availableMatchContexts() const override;
    void setMatchContexts(KeyFilter::MatchContexts value) const;

    QColor fgColor() const override;
    void setFgColor(const QColor &value) const;

    QColor bgColor() const override;
    void setBgColor(const QColor &value) const;

    FontDescription  fontDescription() const override;
    QString name() const override;
    void setName(const QString &value) const;
    QString icon() const override;
    void setIcon(const QString &value) const;
    QFont font() const;
    void setFont(const QFont &value) const;

    TriState revoked() const;
    TriState expired() const;
    TriState disabled() const;
    TriState root() const;
    TriState canEncrypt() const;
    TriState canSign() const;
    TriState canCertify() const;
    TriState canAuthenticate() const;
    TriState qualified() const;
    TriState cardKey() const;
    TriState hasSecret() const;
    TriState isOpenPGP() const;
    TriState wasValidated() const;

    LevelState ownerTrust() const;
    GpgME::Key::OwnerTrust ownerTrustReferenceLevel() const;

    LevelState validity() const;
    GpgME::UserID::Validity validityReferenceLevel() const;
    bool italic() const;
    bool bold() const;
    bool strikeOut() const;
    bool useFullFont() const;

    void setRevoked(const TriState) const;
    void setExpired(const TriState) const;
    void setDisabled(const TriState) const;
    void setRoot(const TriState) const;
    void setCanEncrypt(const TriState) const;
    void setCanSign(const TriState) const;
    void setCanCertify(const TriState) const;
    void setCanAuthenticate(const TriState) const;
    void setQualified(const TriState) const;
    void setCardKey(const TriState) const;
    void setHasSecret(const TriState) const;
    void setIsOpenPGP(const TriState) const;
    void setWasValidated(const TriState) const;

    void setOwnerTrust(const LevelState) const;
    void setOwnerTrustReferenceLevel(const GpgME::Key::OwnerTrust) const;

    void setValidity(const LevelState) const;
    void setValidityReferenceLevel(const GpgME::UserID::Validity) const;

    void setItalic(bool value) const;
    void setBold(bool value) const;
    void setStrikeOut(bool value) const;
    void setUseFullFont(bool value) const;


private:
    class Private;
    const QScopedPointer<Private> d_ptr;
};

} // namespace Kleo
#endif
