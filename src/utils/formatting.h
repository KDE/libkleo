/* -*- mode: c++; c-basic-offset:4 -*-
    utils/formatting.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <gpgme++/key.h>

#include <kleo_export.h>

class QString;
#include <QStringList>
class QDate;
class QIcon;

namespace GpgME
{
class Import;
}

namespace Kleo
{
class KeyGroup;

namespace Formatting
{

KLEO_EXPORT QString prettyNameAndEMail(int proto, const char *id, const char *name, const char *email, const char *comment);
KLEO_EXPORT QString prettyNameAndEMail(int proto, const QString &id, const QString &name, const QString &email, const QString &comment);
KLEO_EXPORT QString prettyNameAndEMail(const GpgME::Key &key);
KLEO_EXPORT QString prettyNameAndEMail(const GpgME::UserID &key);

KLEO_EXPORT QString prettyUserID(const GpgME::UserID &uid);
KLEO_EXPORT QString prettyKeyID(const char *id);

KLEO_EXPORT QString prettyName(int proto, const char *id, const char *name, const char *comment);
KLEO_EXPORT QString prettyName(const GpgME::Key &key);
KLEO_EXPORT QString prettyName(const GpgME::UserID &uid);
KLEO_EXPORT QString prettyName(const GpgME::UserID::Signature &sig);

KLEO_EXPORT QString prettyEMail(const char *email, const char *id);
KLEO_EXPORT QString prettyEMail(const GpgME::Key &key);
KLEO_EXPORT QString prettyEMail(const GpgME::UserID &uid);
KLEO_EXPORT QString prettyEMail(const GpgME::UserID::Signature &sig);

/* Formats a fingerprint or keyid into groups of four */
KLEO_EXPORT QString prettyID(const char *id);

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
    Subkeys          = 0x1000,

    AllOptions = 0xffff
};

KLEO_EXPORT QString toolTip(const GpgME::Key &key, int opts);
KLEO_EXPORT QString toolTip(const Kleo::KeyGroup &group, int opts);

KLEO_EXPORT QString expirationDateString(const GpgME::Key &key);
KLEO_EXPORT QString expirationDateString(const GpgME::Subkey &subkey);
KLEO_EXPORT QString expirationDateString(const GpgME::UserID::Signature &sig);
KLEO_EXPORT QDate expirationDate(const GpgME::Key &key);
KLEO_EXPORT QDate expirationDate(const GpgME::Subkey &subkey);
KLEO_EXPORT QDate expirationDate(const GpgME::UserID::Signature &sig);

KLEO_EXPORT QString creationDateString(const GpgME::Key &key);
KLEO_EXPORT QString creationDateString(const GpgME::Subkey &subkey);
KLEO_EXPORT QString creationDateString(const GpgME::UserID::Signature &sig);
KLEO_EXPORT QDate creationDate(const GpgME::Key &key);
KLEO_EXPORT QDate creationDate(const GpgME::Subkey &subkey);
KLEO_EXPORT QDate creationDate(const GpgME::UserID::Signature &sig);

/* Convert a GPGME style time to a localized string */
KLEO_EXPORT QString dateString(time_t t);

KLEO_EXPORT QString displayName(GpgME::Protocol prot);
KLEO_EXPORT QString type(const GpgME::Key &key);
KLEO_EXPORT QString type(const GpgME::Subkey &subkey);
KLEO_EXPORT QString type(const Kleo::KeyGroup &group);

KLEO_EXPORT QString ownerTrustShort(const GpgME::Key &key);
KLEO_EXPORT QString ownerTrustShort(GpgME::Key::OwnerTrust trust);

KLEO_EXPORT QString validityShort(const GpgME::Subkey &subkey);
KLEO_EXPORT QString validityShort(const GpgME::UserID &uid);
KLEO_EXPORT QString validityShort(const GpgME::UserID::Signature &sig);
KLEO_EXPORT QIcon   validityIcon(const GpgME::UserID::Signature &sig);
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

KLEO_EXPORT QString formatOverview(const GpgME::Key &key);
KLEO_EXPORT QString usageString(const GpgME::Subkey &subkey);
KLEO_EXPORT QString summaryLine(const GpgME::Key &key);
KLEO_EXPORT QString summaryLine(const KeyGroup &group);

KLEO_EXPORT QIcon iconForUid(const GpgME::UserID &uid);

/* Is the key valid i.e. are all uids fully trusted?  */
KLEO_EXPORT bool uidsHaveFullValidity(const GpgME::Key &key);

/* The compliance mode of the gnupg system. Empty if compliance
 * mode is not set. */
KLEO_EXPORT QString complianceMode();

/* Is the given key in compliance with CO_DE_VS?  */
KLEO_EXPORT bool isKeyDeVs(const GpgME::Key &key);
/* Localized string describing the name of the VS-NfD Compliance filter. If
 * compliant is false the name of the not Compliant filter.
 *
 * This is required to make the string configurable which is
 * a common request from users because VS-NfD compliance is called
 * differently in different enviornments. E.g NATO RESTRICTED or
 * EU RESTRICTED. */
KLEO_EXPORT QString deVsString (bool compliant = true);

/* A sentence if the key confirms to the current compliance mode */
KLEO_EXPORT QString complianceStringForKey(const GpgME::Key &key);

/* A single word for use in keylists to describe the validity of the
 * given key, including any conformance statements relevant to the
 * current conformance mode.  */
KLEO_EXPORT QString complianceStringShort(const GpgME::Key &key);
KLEO_EXPORT QString complianceStringShort(const Kleo::KeyGroup &group);

/* The origin of the key mapped to a localized string */
KLEO_EXPORT QString origin(int o);

/* Human-readable trust signature scope (for trust signature regexp created by GnuPG) */
KLEO_EXPORT QString trustSignatureDomain(const GpgME::UserID::Signature &sig);
/* Summary of trust signature properties */
KLEO_EXPORT QString trustSignature(const GpgME::UserID::Signature &sig);
}
}

