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

#include <QColor>
#include <QFont>
#include <QString>

#include <gpgme++/key.h>

#include <memory>

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
        // clang-format off
        DoesNotMatter = 0,
        Set           = 1,
        NotSet        = 2,
        // clang-format on
    };

    /** Used for level checks */
    enum LevelState {
        // clang-format off
        LevelDoesNotMatter = 0,
        Is                 = 1,
        IsNot              = 2,
        IsAtLeast          = 3,
        IsAtMost           = 4,
        // clang-format on
    };

    bool matches(const GpgME::Key &key, MatchContexts ctx) const override;

    unsigned int specificity() const override;
    void setSpecificity(unsigned int value);
    QString id() const override;
    void setId(const QString &value);
    KeyFilter::MatchContexts availableMatchContexts() const override;
    void setMatchContexts(KeyFilter::MatchContexts value);

    QColor fgColor() const override;
    void setFgColor(const QColor &value);

    QColor bgColor() const override;
    void setBgColor(const QColor &value);

    FontDescription fontDescription() const override;
    QString name() const override;
    void setName(const QString &value);
    QString icon() const override;
    void setIcon(const QString &value);
    QFont font() const;
    void setFont(const QFont &value);

    TriState revoked() const;
    TriState expired() const;
    TriState invalid() const;
    TriState disabled() const;
    TriState root() const;
    TriState canEncrypt() const;
    TriState canSign() const;
    TriState canCertify() const;
    TriState canAuthenticate() const;
    TriState hasEncrypt() const;
    TriState hasSign() const;
    TriState hasCertify() const;
    TriState hasAuthenticate() const;
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

    void setRevoked(const TriState);
    void setExpired(const TriState);
    void setInvalid(const TriState);
    void setDisabled(const TriState);
    void setRoot(const TriState);
    void setCanEncrypt(const TriState);
    void setCanSign(const TriState);
    void setCanCertify(const TriState);
    void setCanAuthenticate(const TriState);
    void setHasEncrypt(const TriState);
    void setHasSign(const TriState);
    void setHasCertify(const TriState);
    void setHasAuthenticate(const TriState);
    void setQualified(const TriState);
    void setCardKey(const TriState);
    void setHasSecret(const TriState);
    void setIsOpenPGP(const TriState);
    void setWasValidated(const TriState);
    void setIsDeVs(const TriState);
    void setIsBad(const TriState);
    /**
     * If \p value is \c Set, then invalid S/MIME certificates do not match.
     * If \p value is \c NotSet, then valid S/MIME certificates do not match.
     */
    void setValidIfSMIME(TriState value);
    TriState validIfSMIME() const;

    void setOwnerTrust(const LevelState);
    void setOwnerTrustReferenceLevel(const GpgME::Key::OwnerTrust);

    void setValidity(const LevelState);
    void setValidityReferenceLevel(const GpgME::UserID::Validity);

    void setItalic(bool value);
    void setBold(bool value);
    void setStrikeOut(bool value);
    void setUseFullFont(bool value);

private:
    class Private;
    const std::unique_ptr<Private> d;
};

} // namespace Kleo
