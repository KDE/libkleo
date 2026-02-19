/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2021, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "keyusage.h"

#include "kleo_export.h"

#include <QStringList>

#include <gpgme++/key.h>

class QString;
class QDate;
class QIcon;

namespace GpgME
{
class Error;
class Import;
}

namespace Kleo
{
class KeyGroup;

namespace Formatting
{

class KLEO_EXPORT IconProvider
{
public:
    inline explicit IconProvider(KeyUsage::Flags requiredUsages)
        : usage{requiredUsages}
    {
    }

    QIcon icon(const GpgME::Key &key) const;
    QIcon icon(const KeyGroup &group) const;
    QIcon icon(const GpgME::UserID &userID) const;

private:
    KeyUsage usage;
};

KLEO_EXPORT QIcon successIcon();
KLEO_EXPORT QIcon infoIcon();
KLEO_EXPORT QIcon questionIcon();
KLEO_EXPORT QIcon unavailableIcon();
KLEO_EXPORT QIcon warningIcon();
KLEO_EXPORT QIcon errorIcon();

KLEO_EXPORT QString prettyNameAndEMail(int proto, const char *id, const char *name, const char *email, const char *comment = nullptr);
KLEO_EXPORT QString prettyNameAndEMail(int proto, const QString &id, const QString &name, const QString &email, const QString &comment = {});
KLEO_EXPORT QString prettyNameAndEMail(const GpgME::Key &key);
KLEO_EXPORT QString prettyNameAndEMail(const GpgME::UserID &key);

/*!
 * Returns the name or, if name is empty, the email address of the primary user ID of \a key.
 */
KLEO_EXPORT QString prettyNameOrEMail(const GpgME::Key &key);

KLEO_EXPORT QString prettyUserID(const GpgME::UserID &uid);
KLEO_EXPORT QString prettyKeyID(const char *id);

KLEO_EXPORT QString prettyName(int proto, const char *id, const char *name, const char *comment = nullptr);
KLEO_EXPORT QString prettyName(const GpgME::Key &key);
KLEO_EXPORT QString prettyName(const GpgME::UserID &uid);
KLEO_EXPORT QString prettyName(const GpgME::UserID::Signature &sig);

KLEO_EXPORT QString prettyEMail(const char *email, const char *id);
KLEO_EXPORT QString prettyEMail(const GpgME::Key &key);
KLEO_EXPORT QString prettyEMail(const GpgME::UserID &uid);
KLEO_EXPORT QString prettyEMail(const GpgME::UserID::Signature &sig);

KLEO_EXPORT QString prettyDN(const char *utf8DN);

/* Formats a fingerprint or keyid into groups of four */
KLEO_EXPORT QString prettyID(const char *id);
KLEO_EXPORT QString accessibleHexID(const char *id);

/**
 * Formats a signature from a VerificationResult.
 *
 * @param signature The signature to display.
 * @param sender The sender of the signature, if multiple UserIds are found, this will be the displayed one otherwise the first non empty UserID will be
 * displayed.
 *
 * @note The resulting string will contains links to the key in the following format "key:<fingerprint>".
 */
KLEO_EXPORT QString prettySignature(const GpgME::Signature &signature, const QString &sender);

// clang-format off
enum ToolTipOption {
    KeyID            = 0x001,
    Validity         = 0x002,
    StorageLocation  = 0x004,
    SerialNumber     = 0x008,
    Issuer           = 0x010,
    Subject          = 0x020,
    ExpiryDates      = 0x040,
    CertificateType  = 0x080,
    CertificateUsage = 0x100,
    Fingerprint      = 0x200,
    UserIDs          = 0x400,
    OwnerTrust       = 0x800,

    AllOptions       = 0xffff
};
// clang-format on

KLEO_EXPORT QString toolTip(const GpgME::Key &key, int opts);
KLEO_EXPORT QString toolTip(const Kleo::KeyGroup &group, int opts);
KLEO_EXPORT QString toolTip(const GpgME::UserID &userID, int opts);

/// Returns expiration date of @p key as string, or @p noExpiration if the key doesn't expire.
KLEO_EXPORT QString expirationDateString(const GpgME::Key &key, const QString &noExpiration = {});
/// Returns expiration date of @p subkey as string, or @p noExpiration if the subkey doesn't expire.
KLEO_EXPORT QString expirationDateString(const GpgME::Subkey &subkey, const QString &noExpiration = {});
/// Returns expiration date of @p sig as string, or @p noExpiration if the signature doesn't expire.
KLEO_EXPORT QString expirationDateString(const GpgME::UserID::Signature &sig, const QString &noExpiration = {});
KLEO_EXPORT QDate expirationDate(const GpgME::Key &key);
KLEO_EXPORT QDate expirationDate(const GpgME::Subkey &subkey);
KLEO_EXPORT QDate expirationDate(const GpgME::UserID::Signature &sig);
/**
 * Returns expiration date of @p key as string suitable for screen readers.
 * If the key doesn't expire, then it returns @p noExpiration if @p noExpiration is not empty. Otherwise,
 * returns the localization of "unlimited".
 */
KLEO_EXPORT QString accessibleExpirationDate(const GpgME::Key &key, const QString &noExpiration = {});
/**
 * Returns expiration date of @p subkey as string suitable for screen readers.
 * If the subkey doesn't expire, then it returns @p noExpiration if @p noExpiration is not empty. Otherwise,
 * returns the localization of "unlimited".
 */
KLEO_EXPORT QString accessibleExpirationDate(const GpgME::Subkey &subkey, const QString &noExpiration = {});
/**
 * Returns expiration date of @p sig as string suitable for screen readers.
 * If the signature doesn't expire, then it returns @p noExpiration if @p noExpiration is not empty. Otherwise,
 * returns the localization of "unlimited".
 */
KLEO_EXPORT QString accessibleExpirationDate(const GpgME::UserID::Signature &sig, const QString &noExpiration = {});

KLEO_EXPORT QString creationDateString(const GpgME::Key &key);
KLEO_EXPORT QString creationDateString(const GpgME::Subkey &subkey);
KLEO_EXPORT QString creationDateString(const GpgME::UserID::Signature &sig);
KLEO_EXPORT QDate creationDate(const GpgME::Key &key);
KLEO_EXPORT QDate creationDate(const GpgME::Subkey &subkey);
KLEO_EXPORT QDate creationDate(const GpgME::UserID::Signature &sig);
KLEO_EXPORT QString accessibleCreationDate(const GpgME::Key &key);
KLEO_EXPORT QString accessibleCreationDate(const GpgME::Subkey &subkey);

/* Convert a GPGME style time or a QDate to a localized string */
KLEO_EXPORT QString dateString(time_t t);
KLEO_EXPORT QString dateString(const QDate &date);
KLEO_EXPORT QString accessibleDate(time_t t);
KLEO_EXPORT QString accessibleDate(const QDate &date);

KLEO_EXPORT QString displayName(GpgME::Protocol prot);
KLEO_EXPORT QString type(const GpgME::Key &key);
KLEO_EXPORT QString type(const GpgME::Subkey &subkey);
KLEO_EXPORT QString type(const Kleo::KeyGroup &group);

KLEO_EXPORT QString ownerTrustShort(const GpgME::Key &key);
KLEO_EXPORT QString ownerTrustShort(GpgME::Key::OwnerTrust trust);

KLEO_EXPORT QString validityShort(const GpgME::Subkey &subkey);
KLEO_EXPORT QString validityShort(const GpgME::UserID &uid);
KLEO_EXPORT QString validityShort(const GpgME::UserID::Signature &sig);
KLEO_EXPORT QIcon validityIcon(const GpgME::UserID::Signature &sig);
/* A sentence about the validity of the UserID */
KLEO_EXPORT QString validity(const GpgME::UserID &uid);
KLEO_EXPORT QString validity(const Kleo::KeyGroup &group);
KLEO_EXPORT QIcon validityIcon(const Kleo::KeyGroup &group);

KLEO_EXPORT QString formatForComboBox(const GpgME::Key &key);

KLEO_EXPORT QString formatKeyLink(const GpgME::Key &key);

KLEO_EXPORT QString signatureToString(const GpgME::Signature &sig, const GpgME::Key &key);

KLEO_EXPORT const char *summaryToString(const GpgME::Signature::Summary summary);

KLEO_EXPORT QString importMetaData(const GpgME::Import &import);
KLEO_EXPORT QString importMetaData(const GpgME::Import &import, const QStringList &sources);

KLEO_EXPORT QString usageString(const GpgME::Subkey &subkey);
KLEO_EXPORT QString summaryLine(const GpgME::UserID &id);
KLEO_EXPORT QString summaryLine(const GpgME::Key &key);
KLEO_EXPORT QString summaryLine(const KeyGroup &group);
KLEO_EXPORT QString nameAndEmailForSummaryLine(const GpgME::Key &key);
KLEO_EXPORT QString nameAndEmailForSummaryLine(const GpgME::UserID &id);

KLEO_EXPORT QIcon iconForUid(const GpgME::UserID &uid);

/* The compliance mode of the gnupg system. Empty if compliance
 * mode is not set.
 * Use Kleo::gnupgComplianceMode() instead.
 */
KLEO_DEPRECATED_EXPORT QString complianceMode();

/* A sentence if the key confirms to the current compliance mode */
KLEO_EXPORT QString complianceStringForKey(const GpgME::Key &key);
KLEO_EXPORT QString complianceStringForUserID(const GpgME::UserID &userID);

/* A single word for use in keylists to describe the validity of the
 * given key, including any conformance statements relevant to the
 * current conformance mode.  */
KLEO_EXPORT QString complianceStringShort(const GpgME::Key &key);
KLEO_EXPORT QString complianceStringShort(const GpgME::UserID &id);
KLEO_EXPORT QString complianceStringShort(const Kleo::KeyGroup &group);

/* The origin of the key mapped to a localized string */
KLEO_EXPORT QString origin(int o);

/* Human-readable trust signature scope (for trust signature regexp created by GnuPG) */
KLEO_EXPORT QString trustSignatureDomain(const GpgME::UserID::Signature &sig);
/* Summary of trust signature properties */
KLEO_EXPORT QString trustSignature(const GpgME::UserID::Signature &sig);

/**
 * Returns the value of Error::asString() for the error \p error as Unicode string.
 */
KLEO_EXPORT QString errorAsString(const GpgME::Error &error);

/**
 * Returns a name suitable for being displayed for the GPG algorithm name @p algorithm.
 */
KLEO_EXPORT QString prettyAlgorithmName(const std::string &algorithm);

/**
 * Returns the email associated to a UserID.
 */
KLEO_EXPORT QString email(const GpgME::UserID &uid);
}
}
