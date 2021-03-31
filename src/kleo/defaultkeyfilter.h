/*
    defaultkeyfilter.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "keyfilter.h"

#include "kleo_export.h"

#include <QFont>
#include <QString>
#include <QColor>
#include <QScopedPointer>

#include <gpgme++/key.h>

namespace Kleo
{

/** Default implementation of key filter class. */
class KLEO_EXPORT DefaultKeyFilter : public KeyFilter
{
public:
    DefaultKeyFilter();
    ~DefaultKeyFilter() override;

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
    TriState invalid() const;
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
    TriState isDeVS() const;
    TriState isBad() const;

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
    void setInvalid(const TriState) const;
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
    void setIsDeVs(const TriState) const;
    void setIsBad(const TriState) const;

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
