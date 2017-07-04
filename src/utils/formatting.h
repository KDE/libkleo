/* -*- mode: c++; c-basic-offset:4 -*-
    utils/formatting.h

    This file is part of Kleopatra, the KDE keymanager
    Copyright (c) 2007 Klarälvdalens Datakonsult AB

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

#ifndef __KLEOPATRA_UTILS_FORMATTING_H__
#define __KLEOPATRA_UTILS_FORMATTING_H__

#include <gpgme++/key.h>

#include <kleo_export.h>

class QString;
class QStringList;
class QDate;
class QIcon;

namespace GpgME
{
class Import;
}

namespace Kleo
{
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

    AllOptions = 0xfff
};

KLEO_EXPORT QString toolTip(const GpgME::Key &key, int opts);

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

KLEO_EXPORT QString displayName(GpgME::Protocol prot);
KLEO_EXPORT QString type(const GpgME::Key &key);
KLEO_EXPORT QString type(const GpgME::Subkey &subkey);

KLEO_EXPORT QString ownerTrustShort(const GpgME::Key &key);
KLEO_EXPORT QString ownerTrustShort(GpgME::Key::OwnerTrust trust);

KLEO_EXPORT QString validityShort(const GpgME::Subkey &subkey);
KLEO_EXPORT QString validityShort(const GpgME::UserID &uid);
KLEO_EXPORT QString validityShort(const GpgME::UserID::Signature &sig);
/* A sentence about the validity of the UserID */
KLEO_EXPORT QString validity(const GpgME::UserID &uid);

KLEO_EXPORT QString formatForComboBox(const GpgME::Key &key);

KLEO_EXPORT QString formatKeyLink(const GpgME::Key &key);

KLEO_EXPORT QString signatureToString(const GpgME::Signature &sig, const GpgME::Key &key);

KLEO_EXPORT const char *summaryToString(const GpgME::Signature::Summary summary);

KLEO_EXPORT QString importMetaData(const GpgME::Import &import);
KLEO_EXPORT QString importMetaData(const GpgME::Import &import, const QStringList &sources);

KLEO_EXPORT QString formatOverview(const GpgME::Key &key);
KLEO_EXPORT QString usageString(const GpgME::Subkey &subkey);
KLEO_EXPORT QString summaryLine(const GpgME::Key &key);

KLEO_EXPORT QIcon iconForUid(const GpgME::UserID &uid);

/* Is the key valid i.e. are all uids fully trusted?  */
KLEO_EXPORT bool uidsHaveFullValidity(const GpgME::Key &key);

/* The compliance mode of the gnupg system. Empty if compliance
 * mode is not set. */
KLEO_EXPORT QString complianceMode();

/* Is the given key in compliance with CO_DE_VS?  */
KLEO_EXPORT bool isKeyDeVs(const GpgME::Key &key);

/* A sentence if the key confirms to the current compliance mode */
KLEO_EXPORT QString complianceStringForKey(const GpgME::Key &key);

/* A single word for use in keylists to describe the validity of the
 * given key, including any conformance statements relevant to the
 * current conformance mode.  */
KLEO_EXPORT QString complianceStringShort(const GpgME::Key &key);
}
}

#endif /* __KLEOPATRA_UTILS_FORMATTING_H__ */
