/* -*- mode: c++; c-basic-offset: 4; indent-tabs-mode: nil; -*-
    utils/formatting.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2021, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "formatting.h"

#include "algorithm.h"
#include "compat.h"
#include "compliance.h"
#include "cryptoconfig.h"
#include "gnupg.h"
#include "keyhelpers.h"

#include <libkleo/dnattributes.h>
#include <libkleo/keycache.h>
#include <libkleo/keygroup.h>

#include <libkleo_debug.h>

#include <KEmailAddress>
#include <KLocalizedString>

#include <QGpgME/CryptoConfig>
#include <QGpgME/DN>
#include <QGpgME/Protocol>

#include <QDateTime>
#include <QIcon>
#include <QLocale>
#include <QRegularExpression>
#include <QString>

#include <gpgme++/importresult.h>
#include <gpgme++/key.h>

#include <gpg-error.h>

using namespace GpgME;
using namespace Kleo;

using namespace Qt::Literals::StringLiterals;

namespace
{
QIcon iconForValidityAndCompliance(UserID::Validity validity, bool isCompliant)
{
    switch (validity) {
    case UserID::Ultimate:
    case UserID::Full:
    case UserID::Marginal:
        return isCompliant ? Formatting::successIcon() : Formatting::infoIcon();
    case UserID::Never:
        return Formatting::errorIcon();
    case UserID::Undefined:
    case UserID::Unknown:
    default:
        return Formatting::infoIcon();
    }
}
QIcon iconForValidity(const UserID &userId)
{
    const bool keyIsCompliant = !DeVSCompliance::isActive() || //
        (DeVSCompliance::isCompliant() && DeVSCompliance::keyIsCompliant(userId.parent()));
    return iconForValidityAndCompliance(userId.validity(), keyIsCompliant);
}
}

QIcon Formatting::IconProvider::icon(const GpgME::Key &key) const
{
    return icon(key.userID(0));
}

QIcon Formatting::IconProvider::icon(const GpgME::UserID &userID) const
{
    if (usage.canEncrypt() && !Kleo::canBeUsedForEncryption(userID.parent())) {
        return Formatting::errorIcon();
    }
    if (usage.canSign() && !Kleo::canBeUsedForSigning(userID.parent())) {
        return Formatting::errorIcon();
    }
    if (userID.parent().isBad() || userID.isBad()) {
        return Formatting::errorIcon();
    }
    if (Kleo::isRevokedOrExpired(userID)) {
        return Formatting::errorIcon();
    }
    return iconForValidity(userID);
}

QIcon Formatting::IconProvider::icon(const KeyGroup &group) const
{
    if (usage.canEncrypt() && !Kleo::all_of(group.keys(), Kleo::canBeUsedForEncryption)) {
        return Formatting::errorIcon();
    }
    if (usage.canSign() && !Kleo::all_of(group.keys(), Kleo::canBeUsedForSigning)) {
        return Formatting::errorIcon();
    }
    return validityIcon(group);
}

QIcon Formatting::successIcon()
{
    return QIcon::fromTheme(QStringLiteral("data-success"));
}

QIcon Formatting::infoIcon()
{
    return QIcon::fromTheme(QStringLiteral("data-information"));
}

QIcon Formatting::questionIcon()
{
    return QIcon::fromTheme(QStringLiteral("data-question"), QIcon::fromTheme(QStringLiteral("dialog-question")));
}

QIcon Formatting::unavailableIcon()
{
    return QIcon::fromTheme(QStringLiteral("emblem-unavailable"));
}

QIcon Formatting::warningIcon()
{
    return QIcon::fromTheme(QStringLiteral("data-warning"));
}

QIcon Formatting::errorIcon()
{
    return QIcon::fromTheme(QStringLiteral("data-error"));
}

//
// Name
//

QString Formatting::prettyName(int proto, const char *id, const char *name_, const char *comment_)
{
    if (proto == GpgME::OpenPGP) {
        const QString name = QString::fromUtf8(name_);
        if (name.isEmpty()) {
            return QString();
        }
        const QString comment = QString::fromUtf8(comment_);
        if (comment.isEmpty()) {
            return name;
        }
        return QStringLiteral("%1 (%2)").arg(name, comment);
    }

    if (proto == GpgME::CMS) {
        const QGpgME::DN subject(id);
        const QString cn = subject[QStringLiteral("CN")].trimmed();
        if (cn.isEmpty()) {
            subject.setAttributeOrder(DNAttributes::order());
            return subject.prettyDN();
        }
        return cn;
    }

    return QString();
}

QString Formatting::prettyNameAndEMail(int proto, const char *id, const char *name_, const char *email_, const char *comment_)
{
    return prettyNameAndEMail(proto, QString::fromUtf8(id), QString::fromUtf8(name_), prettyEMail(email_, id), QString::fromUtf8(comment_));
}

QString Formatting::prettyNameAndEMail(int proto, const QString &id, const QString &name, const QString &email, const QString &comment)
{
    if (proto == GpgME::OpenPGP) {
        if (name.isEmpty()) {
            if (email.isEmpty()) {
                return QString();
            } else if (comment.isEmpty()) {
                return QStringLiteral("<%1>").arg(email);
            } else {
                return QStringLiteral("(%2) <%1>").arg(email, comment);
            }
        }
        if (email.isEmpty()) {
            if (comment.isEmpty()) {
                return name;
            } else {
                return QStringLiteral("%1 (%2)").arg(name, comment);
            }
        }
        if (comment.isEmpty()) {
            return QStringLiteral("%1 <%2>").arg(name, email);
        } else {
            return QStringLiteral("%1 (%3) <%2>").arg(name, email, comment);
        }
    }

    if (proto == GpgME::CMS) {
        const QGpgME::DN subject(id);
        const QString cn = subject[QStringLiteral("CN")].trimmed();
        if (cn.isEmpty()) {
            subject.setAttributeOrder(DNAttributes::order());
            return subject.prettyDN();
        }
        return cn;
    }
    return QString();
}

QString Formatting::prettyUserID(const UserID &uid)
{
    if (uid.parent().protocol() == GpgME::OpenPGP) {
        return prettyNameAndEMail(uid);
    }
    const QByteArray id = QByteArray(uid.id()).trimmed();
    if (id.startsWith('<')) {
        return prettyEMail(uid.email(), uid.id());
    }
    if (id.startsWith('(')) {
        // ### parse uri/dns:
        return QString::fromUtf8(uid.id());
    } else {
        return prettyDN(uid.id());
    }
}

QString Formatting::prettyKeyID(const char *id)
{
    if (!id) {
        return QString();
    }
    return QLatin1StringView("0x") + QString::fromLatin1(id).toUpper();
}

QString Formatting::prettyNameAndEMail(const UserID &uid)
{
    return prettyNameAndEMail(uid.parent().protocol(), uid.id(), uid.name(), uid.email(), uid.comment());
}

QString Formatting::prettyNameAndEMail(const Key &key)
{
    return prettyNameAndEMail(key.userID(0));
}

QString Formatting::prettyName(const Key &key)
{
    return prettyName(key.userID(0));
}

QString Formatting::prettyName(const UserID &uid)
{
    return prettyName(uid.parent().protocol(), uid.id(), uid.name(), uid.comment());
}

QString Formatting::prettyName(const UserID::Signature &sig)
{
    return prettyName(GpgME::OpenPGP, sig.signerUserID(), sig.signerName(), sig.signerComment());
}

//
// EMail
//

QString Formatting::prettyEMail(const Key &key)
{
    for (unsigned int i = 0, end = key.numUserIDs(); i < end; ++i) {
        const QString email = prettyEMail(key.userID(i));
        if (!email.isEmpty()) {
            return email;
        }
    }
    return QString();
}

QString Formatting::prettyEMail(const UserID &uid)
{
    return prettyEMail(uid.email(), uid.id());
}

QString Formatting::prettyEMail(const UserID::Signature &sig)
{
    return prettyEMail(sig.signerEmail(), sig.signerUserID());
}

QString Formatting::prettyEMail(const char *email_, const char *id)
{
    QString email;
    QString name;
    QString comment;
    if (email_ && KEmailAddress::splitAddress(QString::fromUtf8(email_), name, email, comment) == KEmailAddress::AddressOk) {
        return email;
    } else {
        return QGpgME::DN(id)[QStringLiteral("EMAIL")].trimmed();
    }
}

QString Formatting::prettyDN(const char *utf8DN)
{
    QGpgME::DN dn{utf8DN};
    dn.setAttributeOrder(DNAttributes::order());
    return dn.prettyDN();
}

//
// Tooltip
//

namespace
{

static QString protect_whitespace(QString s)
{
    static const QLatin1Char SP(' ');
    static const QLatin1Char NBSP('\xA0');
    return s.replace(SP, NBSP);
}

template<typename T_arg>
QString format_row(const QString &field, const T_arg &arg)
{
    return QStringLiteral("<tr><th>%1:</th><td>%2</td></tr>").arg(protect_whitespace(field), arg);
}
QString format_row(const QString &field, const QString &arg)
{
    return QStringLiteral("<tr><th>%1:</th><td>%2</td></tr>").arg(protect_whitespace(field), arg.toHtmlEscaped());
}
QString format_row(const QString &field, const char *arg)
{
    return format_row(field, QString::fromUtf8(arg));
}

QString format_keytype(const Key &key)
{
    const Subkey subkey = key.subkey(0);
    if (key.hasSecret()) {
        return i18n("%1-bit %2 (secret key available)", subkey.length(), QLatin1StringView(subkey.publicKeyAlgorithmAsString()));
    } else {
        return i18n("%1-bit %2", subkey.length(), QLatin1StringView(subkey.publicKeyAlgorithmAsString()));
    }
}

QString format_keyusage(const Key &key)
{
    QStringList capabilities;
    if (Kleo::keyHasSign(key)) {
        if (key.isQualified()) {
            capabilities.push_back(i18n("Signing (Qualified)"));
        } else {
            capabilities.push_back(i18n("Signing"));
        }
    }
    if (Kleo::keyHasEncrypt(key)) {
        capabilities.push_back(i18n("Encryption"));
    }
    if (Kleo::keyHasCertify(key)) {
        capabilities.push_back(i18n("Certifying User IDs"));
    }
    if (Kleo::keyHasAuthenticate(key)) {
        capabilities.push_back(i18n("SSH Authentication"));
    }
    return capabilities.join(QLatin1StringView(", "));
}

static QString time_t2string(time_t t)
{
    const QDateTime dt = QDateTime::fromSecsSinceEpoch(quint32(t));
    return QLocale().toString(dt, QLocale::ShortFormat);
}

static QString make_red(const QString &txt)
{
    return QLatin1StringView("<font color=\"red\">") + txt.toHtmlEscaped() + QLatin1StringView("</font>");
}

}

static QString toolTipInternal(const GpgME::Key &key, const GpgME::UserID &userID, int flags)
{
    if (flags == 0 || (key.protocol() != GpgME::CMS && key.protocol() != GpgME::OpenPGP)) {
        return QString();
    }

    const Subkey subkey = key.subkey(0);

    QString result;
    if (flags & Formatting::Validity) {
        if (key.protocol() == GpgME::OpenPGP || (key.keyListMode() & Validate)) {
            if (key.isDisabled()) {
                result = i18n("Disabled");
            } else if (userID.isRevoked() || key.isRevoked()) {
                result = make_red(i18n("Revoked"));
            } else if (key.isExpired()) {
                result = make_red(i18n("Expired"));
            } else if (key.keyListMode() & GpgME::Validate) {
                if (!userID.isNull()) {
                    if (userID.validity() >= UserID::Validity::Full) {
                        result = i18n("User ID is certified.");
                        const auto compliance = Formatting::complianceStringForUserID(userID);
                        if (!compliance.isEmpty()) {
                            result += QStringLiteral("<br>") + compliance;
                        }
                    } else {
                        result = i18n("User ID is not certified.");
                    }
                } else {
                    unsigned int fullyTrusted = 0;
                    for (const auto &uid : key.userIDs()) {
                        if (uid.validity() >= UserID::Validity::Full) {
                            fullyTrusted++;
                        }
                    }
                    if (fullyTrusted == key.numUserIDs()) {
                        result = i18n("All User IDs are certified.");
                        const auto compliance = Formatting::complianceStringForKey(key);
                        if (!compliance.isEmpty()) {
                            result += QStringLiteral("<br>") + compliance;
                        }
                    } else {
                        result = i18np("One User ID is not certified.", "%1 User IDs are not certified.", key.numUserIDs() - fullyTrusted);
                    }
                }
            } else {
                result = i18n("The validity cannot be checked at the moment.");
            }
        } else {
            result = i18n("The validity cannot be checked at the moment.");
        }
    }
    if (flags == Formatting::Validity) {
        return result;
    }

    result += QLatin1StringView("<table border=\"0\">");
    if (key.protocol() == GpgME::CMS) {
        if (flags & Formatting::SerialNumber) {
            result += format_row(i18n("Serial number"), key.issuerSerial());
        }
        if (flags & Formatting::Issuer) {
            result += format_row(i18n("Issuer"), key.issuerName());
        }
    }
    if (flags & Formatting::UserIDs) {
        if (userID.isNull()) {
            const std::vector<UserID> uids = key.userIDs();
            if (!uids.empty()) {
                result += format_row(key.protocol() == GpgME::CMS ? i18n("Subject") : i18n("User ID"), Formatting::prettyUserID(uids.front()));
            }
            if (uids.size() > 1) {
                for (auto it = uids.begin() + 1, end = uids.end(); it != end; ++it) {
                    if (!it->isRevoked() && !it->isInvalid()) {
                        result += format_row(i18n("a.k.a."), Formatting::prettyUserID(*it));
                    }
                }
            }
        } else {
            result += format_row(key.protocol() == GpgME::CMS ? i18n("Subject") : i18n("User ID"), Formatting::prettyUserID(userID));
        }
    }
    if (flags & Formatting::ExpiryDates) {
        result += format_row(i18n("Valid from"), time_t2string(subkey.creationTime()));

        if (!subkey.neverExpires()) {
            result += format_row(i18n("Valid until"), time_t2string(subkey.expirationTime()));
        }
    }

    if (flags & Formatting::CertificateType) {
        result += format_row(i18n("Type"), format_keytype(key));
    }
    if (flags & Formatting::CertificateUsage) {
        result += format_row(i18n("Usage"), format_keyusage(key));
    }
    if (flags & Formatting::KeyID) {
        result += format_row(i18n("Key ID"), QString::fromLatin1(key.keyID()));
    }
    if (flags & Formatting::Fingerprint) {
        result += format_row(i18n("Fingerprint"), Formatting::prettyID(key.primaryFingerprint()));
    }
    if (flags & Formatting::OwnerTrust) {
        if (key.protocol() == GpgME::OpenPGP) {
            result += format_row(i18n("Certification trust"), Formatting::ownerTrustShort(key));
        } else if (key.isRoot()) {
            result += format_row(i18n("Trusted issuer?"), (userID.isNull() ? key.userID(0) : userID).validity() == UserID::Ultimate ? i18n("Yes") : i18n("No"));
        }
    }
    if (flags & Formatting::StorageLocation) {
        if (const char *card = subkey.cardSerialNumber()) {
            result += format_row(i18n("Stored"), i18nc("stored...", "on SmartCard with serial no. %1", QString::fromUtf8(card)));
        } else {
            result += format_row(i18n("Stored"), i18nc("stored...", "on this computer"));
        }
    }
    result += QLatin1StringView("</table>");

    return result;
}

QString Formatting::toolTip(const Key &key, int flags)
{
    return toolTipInternal(key, UserID(), flags);
}

namespace
{
template<typename Container>
QString getValidityStatement(const Container &keys)
{
    const bool allKeysAreOpenPGP = std::all_of(keys.cbegin(), keys.cend(), [](const Key &key) {
        return key.protocol() == GpgME::OpenPGP;
    });
    const bool allKeysAreValidated = std::all_of(keys.cbegin(), keys.cend(), [](const Key &key) {
        return key.keyListMode() & Validate;
    });
    if (allKeysAreOpenPGP || allKeysAreValidated) {
        const bool someKeysAreBad = std::any_of(keys.cbegin(), keys.cend(), std::mem_fn(&Key::isBad));
        if (someKeysAreBad) {
            return i18n("Some keys are revoked, expired, disabled, or invalid.");
        } else {
            const bool allKeysAreFullyValid = std::all_of(keys.cbegin(), keys.cend(), &Kleo::allUserIDsHaveFullValidity);
            if (allKeysAreFullyValid) {
                return i18n("All keys are certified.");
            } else {
                return i18n("Some keys are not certified.");
            }
        }
    }
    return i18n("The validity of the keys cannot be checked at the moment.");
}
}

QString Formatting::toolTip(const KeyGroup &group, int flags)
{
    static const unsigned int maxNumKeysForTooltip = 20;

    if (group.isNull()) {
        return QString();
    }

    const KeyGroup::Keys &keys = group.keys();
    if (keys.size() == 0) {
        return i18nc("@info:tooltip", "This group does not contain any keys.");
    }

    if (Kleo::any_of(keys, [](const auto &key) {
            return !key.hasEncrypt();
        })) {
        return i18nc("@info:tooltip", "Some of the certificates in this group cannot be used for encryption. Using this group can lead to unexpected results.");
    }

    const QString validity = (flags & Validity) ? getValidityStatement(keys) : QString();
    if (flags == Validity) {
        return validity;
    }

    // list either up to maxNumKeysForTooltip keys or (maxNumKeysForTooltip-1) keys followed by "and n more keys"
    const unsigned int numKeysForTooltip = keys.size() > maxNumKeysForTooltip ? maxNumKeysForTooltip - 1 : keys.size();

    QStringList result;
    result.reserve(3 + 2 + numKeysForTooltip + 2);
    if (!validity.isEmpty()) {
        result.push_back(QStringLiteral("<p>"));
        result.push_back(validity.toHtmlEscaped());
        result.push_back(QStringLiteral("</p>"));
    }

    result.push_back(QStringLiteral("<p>"));
    result.push_back(i18n("Keys:"));
    {
        auto it = keys.cbegin();
        for (unsigned int i = 0; i < numKeysForTooltip; ++i, ++it) {
            result.push_back(QLatin1StringView("<br>") + Formatting::summaryLine(*it).toHtmlEscaped());
        }
    }
    if (keys.size() > numKeysForTooltip) {
        result.push_back(QLatin1StringView("<br>")
                         + i18ncp("this follows a list of keys", "and 1 more key", "and %1 more keys", keys.size() - numKeysForTooltip));
    }
    result.push_back(QStringLiteral("</p>"));

    return result.join(QLatin1Char('\n'));
}

QString Formatting::toolTip(const UserID &userID, int flags)
{
    return toolTipInternal(userID.parent(), userID, flags);
}

//
// Creation and Expiration
//

namespace
{
static QDate time_t2date(time_t t)
{
    if (!t) {
        return {};
    }
    const QDateTime dt = QDateTime::fromSecsSinceEpoch(quint32(t));
    return dt.date();
}
static QString accessible_date_format()
{
    return i18nc(
        "date format suitable for screen readers; "
        "d: day as a number without a leading zero, "
        "MMMM: localized month name, "
        "yyyy: year as a four digit number",
        "MMMM d, yyyy");
}

template<typename T>
QString expiration_date_string(const T &tee, const QString &noExpiration)
{
    return tee.neverExpires() ? noExpiration : Formatting::dateString(time_t2date(tee.expirationTime()));
}
template<typename T>
QDate creation_date(const T &tee)
{
    return time_t2date(tee.creationTime());
}
template<typename T>
QDate expiration_date(const T &tee)
{
    return time_t2date(tee.expirationTime());
}
}

QString Formatting::dateString(time_t t)
{
    return dateString(time_t2date(t));
}

QString Formatting::dateString(const QDate &date)
{
    return QLocale().toString(date, QLocale::ShortFormat);
}

QString Formatting::accessibleDate(time_t t)
{
    return accessibleDate(time_t2date(t));
}

QString Formatting::accessibleDate(const QDate &date)
{
    return QLocale().toString(date, accessible_date_format());
}

QString Formatting::expirationDateString(const Key &key, const QString &noExpiration)
{
    // if key is remote but has a non-zero expiration date (e.g. a key looked up via WKD),
    // then we assume that the date is valid; if the date is zero for a remote key, then
    // we don't know if it's unknown or unlimited
    return isRemoteKey(key) && (key.subkey(0).expirationTime() == 0) //
        ? i18nc("@info the expiration date of the key is unknown", "unknown")
        : expiration_date_string(key.subkey(0), noExpiration);
}

QString Formatting::expirationDateString(const Subkey &subkey, const QString &noExpiration)
{
    return expiration_date_string(subkey, noExpiration);
}

QString Formatting::expirationDateString(const UserID::Signature &sig, const QString &noExpiration)
{
    return expiration_date_string(sig, noExpiration);
}

QDate Formatting::expirationDate(const Key &key)
{
    return expiration_date(key.subkey(0));
}

QDate Formatting::expirationDate(const Subkey &subkey)
{
    return expiration_date(subkey);
}

QDate Formatting::expirationDate(const UserID::Signature &sig)
{
    return expiration_date(sig);
}

QString Formatting::accessibleExpirationDate(const Key &key, const QString &noExpiration)
{
    // if key is remote but has a non-zero expiration date (e.g. a key looked up via WKD),
    // then we assume that the date is valid; if the date is zero for a remote key, then
    // we don't know if it's unknown or unlimited
    return isRemoteKey(key) && (key.subkey(0).expirationTime() == 0) //
        ? i18nc("@info the expiration date of the key is unknown", "unknown")
        : accessibleExpirationDate(key.subkey(0), noExpiration);
}

QString Formatting::accessibleExpirationDate(const Subkey &subkey, const QString &noExpiration)
{
    if (subkey.neverExpires()) {
        return noExpiration.isEmpty() ? i18n("unlimited") : noExpiration;
    } else {
        return accessibleDate(expirationDate(subkey));
    }
}

QString Formatting::accessibleExpirationDate(const UserID::Signature &sig, const QString &noExpiration)
{
    if (sig.neverExpires()) {
        return noExpiration.isEmpty() ? i18n("unlimited") : noExpiration;
    } else {
        return accessibleDate(expirationDate(sig));
    }
}

QString Formatting::creationDateString(const Key &key)
{
    return dateString(creation_date(key.subkey(0)));
}

QString Formatting::creationDateString(const Subkey &subkey)
{
    return dateString(creation_date(subkey));
}

QString Formatting::creationDateString(const UserID::Signature &sig)
{
    return dateString(creation_date(sig));
}

QDate Formatting::creationDate(const Key &key)
{
    return creation_date(key.subkey(0));
}

QDate Formatting::creationDate(const Subkey &subkey)
{
    return creation_date(subkey);
}

QDate Formatting::creationDate(const UserID::Signature &sig)
{
    return creation_date(sig);
}

QString Formatting::accessibleCreationDate(const Key &key)
{
    return accessibleDate(creationDate(key));
}

QString Formatting::accessibleCreationDate(const Subkey &subkey)
{
    return accessibleDate(creationDate(subkey));
}

//
// Types
//

QString Formatting::displayName(GpgME::Protocol p)
{
    if (p == GpgME::CMS) {
        return i18nc("X.509/CMS encryption standard", "S/MIME");
    }
    if (p == GpgME::OpenPGP) {
        return i18n("OpenPGP");
    }
    return i18nc("Unknown encryption protocol", "Unknown");
}

QString Formatting::type(const Key &key)
{
    return displayName(key.protocol());
}

QString Formatting::type(const Subkey &subkey)
{
    return QString::fromUtf8(subkey.publicKeyAlgorithmAsString());
}

QString Formatting::type(const KeyGroup &group)
{
    Q_UNUSED(group)
    return i18nc("a group of keys/certificates", "Group");
}

//
// Status / Validity
//

QString Formatting::ownerTrustShort(const Key &key)
{
    return ownerTrustShort(key.ownerTrust());
}

QString Formatting::ownerTrustShort(Key::OwnerTrust trust)
{
    switch (trust) {
    case Key::Unknown:
        return i18nc("unknown trust level", "unknown");
    case Key::Never:
        return i18n("untrusted");
    case Key::Marginal:
        return i18nc("marginal trust", "marginal");
    case Key::Full:
        return i18nc("full trust", "full");
    case Key::Ultimate:
        return i18nc("ultimate trust", "ultimate");
    case Key::Undefined:
        return i18nc("undefined trust", "undefined");
    default:
        Q_ASSERT(!"unexpected owner trust value");
        break;
    }
    return QString();
}

QString Formatting::validityShort(const Subkey &subkey)
{
    if (subkey.isDisabled()) {
        return i18n("disabled");
    }
    if (subkey.isRevoked()) {
        return i18n("revoked");
    }
    if (subkey.isExpired()) {
        return i18n("expired");
    }
    if (subkey.isInvalid()) {
        return i18n("invalid");
    }
    return i18nc("as in 'this subkey is ok'", "OK");
}

QString Formatting::validityShort(const UserID &uid)
{
    if (uid.isRevoked()) {
        return i18n("revoked");
    }
    if (uid.isInvalid()) {
        return i18n("invalid");
    }
    switch (uid.validity()) {
    case UserID::Unknown:
        return i18nc("unknown trust level", "unknown");
    case UserID::Undefined:
        return i18nc("undefined trust", "undefined");
    case UserID::Never:
        return i18n("untrusted");
    case UserID::Marginal:
        return i18nc("marginal trust", "marginal");
    case UserID::Full:
        return i18nc("full trust", "full");
    case UserID::Ultimate:
        return i18nc("ultimate trust", "ultimate");
    }
    return QString();
}

QString Formatting::validityShort(const UserID::Signature &sig)
{
    switch (sig.status()) {
    case UserID::Signature::NoError:
        if (!sig.isInvalid()) {
            /* See RFC 4880 Section 5.2.1 */
            switch (sig.certClass()) {
            case 0x10: /* Generic */
            case 0x11: /* Persona */
            case 0x12: /* Casual */
            case 0x13: /* Positive */
                return i18n("valid");
            case 0x30:
                return i18n("revoked");
            default:
                return i18n("class %1", sig.certClass());
            }
        }
        [[fallthrough]];
        // fall through:
    case UserID::Signature::GeneralError:
        return i18n("invalid");
    case UserID::Signature::SigExpired:
        return i18n("expired");
    case UserID::Signature::KeyExpired:
        return i18n("certificate expired");
    case UserID::Signature::BadSignature:
        return i18nc("fake/invalid signature", "bad");
    case UserID::Signature::NoPublicKey: {
        /* GnuPG returns the same error for no public key as for expired
         * or revoked certificates. */
        const auto key = KeyCache::instance()->findByKeyIDOrFingerprint(sig.signerKeyID());
        if (key.isNull()) {
            return i18n("no public key");
        } else if (key.isDisabled()) {
            return i18n("key disabled");
        } else if (key.isRevoked()) {
            return i18n("key revoked");
        } else if (key.isExpired()) {
            return i18n("key expired");
        }
        /* can't happen */
        return QStringLiteral("unknown");
    }
    }
    return QString();
}

QIcon Formatting::validityIcon(const UserID::Signature &sig)
{
    switch (sig.status()) {
    case UserID::Signature::NoError:
        if (!sig.isInvalid()) {
            /* See RFC 4880 Section 5.2.1 */
            switch (sig.certClass()) {
            case 0x10: /* Generic */
            case 0x11: /* Persona */
            case 0x12: /* Casual */
            case 0x13: /* Positive */
                return Formatting::successIcon();
            case 0x30:
                return Formatting::errorIcon();
            default:
                return QIcon();
            }
        }
        [[fallthrough]];
        // fall through:
    case UserID::Signature::BadSignature:
    case UserID::Signature::GeneralError:
        return Formatting::errorIcon();
    case UserID::Signature::SigExpired:
    case UserID::Signature::KeyExpired:
        return Formatting::infoIcon();
    case UserID::Signature::NoPublicKey:
        return Formatting::questionIcon();
    }
    return QIcon();
}

QString Formatting::formatKeyLink(const Key &key)
{
    if (key.isNull()) {
        return QString();
    }
    return QStringLiteral("<a href=\"key:%1\">%2</a>").arg(QLatin1StringView(key.primaryFingerprint()), Formatting::prettyName(key));
}

QString Formatting::formatForComboBox(const GpgME::Key &key)
{
    const QString name = prettyName(key);
    QString mail = prettyEMail(key);
    if (!mail.isEmpty()) {
        mail = QLatin1Char('<') + mail + QLatin1Char('>');
    }
    return i18nc("name, email, key id", "%1 %2 (%3)", name, mail, Formatting::prettyID(key.keyID())).simplified();
}

QString Formatting::nameAndEmailForSummaryLine(const UserID &id)
{
    Q_ASSERT(!id.isNull());

    const QString email = Formatting::prettyEMail(id);
    const QString name = Formatting::prettyName(id);

    if (name.isEmpty()) {
        return email;
    } else if (email.isEmpty()) {
        return name;
    } else {
        return QStringLiteral("%1 <%2>").arg(name, email);
    }
}

QString Formatting::nameAndEmailForSummaryLine(const Key &key)
{
    Q_ASSERT(!key.isNull());

    const QString email = Formatting::prettyEMail(key);
    const QString name = Formatting::prettyName(key);

    if (name.isEmpty()) {
        return email;
    } else if (email.isEmpty()) {
        return name;
    } else {
        return QStringLiteral("%1 <%2>").arg(name, email);
    }
}

const char *Formatting::summaryToString(const Signature::Summary summary)
{
    if (summary & Signature::Red) {
        return "RED";
    }
    if (summary & Signature::Green) {
        return "GREEN";
    }
    return "YELLOW";
}

QString Formatting::signatureToString(const Signature &sig, const Key &key)
{
    if (sig.isNull()) {
        return QString();
    }

    const bool red = (sig.summary() & Signature::Red);
    const bool valid = (sig.summary() & Signature::Valid);

    if (red) {
        if (key.isNull()) {
            if (const char *fpr = sig.fingerprint()) {
                return i18n("Bad signature by unknown certificate %1: %2", QString::fromLatin1(fpr), Formatting::errorAsString(sig.status()));
            } else {
                return i18n("Bad signature by an unknown certificate: %1", Formatting::errorAsString(sig.status()));
            }
        } else {
            return i18n("Bad signature by %1: %2", nameAndEmailForSummaryLine(key), Formatting::errorAsString(sig.status()));
        }

    } else if (valid) {
        if (key.isNull()) {
            if (const char *fpr = sig.fingerprint()) {
                return i18n("Good signature by unknown certificate %1.", QString::fromLatin1(fpr));
            } else {
                return i18n("Good signature by an unknown certificate.");
            }
        } else {
            return i18n("Good signature by %1.", nameAndEmailForSummaryLine(key));
        }

    } else if (key.isNull()) {
        if (const char *fpr = sig.fingerprint()) {
            return i18n("Invalid signature by unknown certificate %1: %2", QString::fromLatin1(fpr), Formatting::errorAsString(sig.status()));
        } else {
            return i18n("Invalid signature by an unknown certificate: %1", Formatting::errorAsString(sig.status()));
        }
    } else {
        return i18n("Invalid signature by %1: %2", nameAndEmailForSummaryLine(key), Formatting::errorAsString(sig.status()));
    }
}

//
// ImportResult
//

QString Formatting::importMetaData(const Import &import, const QStringList &ids)
{
    const QString result = importMetaData(import);
    if (result.isEmpty()) {
        return QString();
    } else {
        return result + QLatin1Char('\n') + i18n("This certificate was imported from the following sources:") + QLatin1Char('\n') + ids.join(QLatin1Char('\n'));
    }
}

QString Formatting::importMetaData(const Import &import)
{
    if (import.isNull()) {
        return QString();
    }

    if (import.error().isCanceled()) {
        return i18n("The import of this certificate was canceled.");
    }
    if (import.error()) {
        return i18n("An error occurred importing this certificate: %1", Formatting::errorAsString(import.error()));
    }

    const unsigned int status = import.status();
    if (status & Import::NewKey) {
        return (status & Import::ContainedSecretKey) ? i18n("This certificate was new to your keystore. The secret key is available.")
                                                     : i18n("This certificate is new to your keystore.");
    }

    QStringList results;
    if (status & Import::NewUserIDs) {
        results.push_back(i18n("New user-ids were added to this certificate by the import."));
    }
    if (status & Import::NewSignatures) {
        results.push_back(i18n("New signatures were added to this certificate by the import."));
    }
    if (status & Import::NewSubkeys) {
        results.push_back(i18n("New subkeys were added to this certificate by the import."));
    }

    return results.empty() ? i18n("The import contained no new data for this certificate. It is unchanged.") : results.join(QLatin1Char('\n'));
}

QString Formatting::usageString(const Subkey &sub)
{
    QStringList usageStrings;
    if (sub.canCertify()) {
        usageStrings << i18n("Certify");
    }
    if (sub.canSign()) {
        usageStrings << i18n("Sign");
    }
    if (sub.canEncrypt()) {
        usageStrings << i18n("Encrypt");
    }
    if (sub.canAuthenticate()) {
        usageStrings << i18n("Authenticate");
    }
    if (sub.canRenc()) {
        usageStrings << i18nc("Means 'Additional Decryption Subkey'; Don't try translating that, though.", "ADSK");
    }
    return usageStrings.join(QLatin1StringView(", "));
}

QString Formatting::summaryLine(const UserID &id)
{
    return i18nc("name <email> (validity, protocol, creation date)",
                 "%1 (%2, %3, created: %4)",
                 nameAndEmailForSummaryLine(id),
                 Formatting::complianceStringShort(id),
                 displayName(id.parent().protocol()),
                 Formatting::creationDateString(id.parent()));
}

QString Formatting::summaryLine(const Key &key)
{
    return nameAndEmailForSummaryLine(key) + QLatin1Char(' ')
        + i18nc("(validity, protocol, creation date)",
                "(%1, %2, created: %3)",
                Formatting::complianceStringShort(key),
                displayName(key.protocol()),
                Formatting::creationDateString(key));
}

QString Formatting::summaryLine(const KeyGroup &group)
{
    switch (group.source()) {
    case KeyGroup::ApplicationConfig:
    case KeyGroup::GnuPGConfig:
        return i18ncp("name of group of keys (n key(s), validity)",
                      "%2 (1 key, %3)",
                      "%2 (%1 keys, %3)",
                      group.keys().size(),
                      group.name(),
                      Formatting::complianceStringShort(group));
    case KeyGroup::Tags:
        return i18ncp("name of group of keys (n key(s), validity, tag)",
                      "%2 (1 key, %3, tag)",
                      "%2 (%1 keys, %3, tag)",
                      group.keys().size(),
                      group.name(),
                      Formatting::complianceStringShort(group));
    default:
        return i18ncp("name of group of keys (n key(s), validity, group ...)",
                      "%2 (1 key, %3, unknown origin)",
                      "%2 (%1 keys, %3, unknown origin)",
                      group.keys().size(),
                      group.name(),
                      Formatting::complianceStringShort(group));
    }
}

// Icon for certificate selection indication
QIcon Formatting::iconForUid(const UserID &uid)
{
    if (Kleo::isRevokedOrExpired(uid)) {
        return Formatting::errorIcon();
    }
    return iconForValidity(uid);
}

QString Formatting::validity(const UserID &uid)
{
    switch (uid.validity()) {
    case UserID::Ultimate:
        return i18n("The certificate is marked as your own.");
    case UserID::Full:
        return i18n("The certificate belongs to this recipient.");
    case UserID::Marginal:
        return i18n("The trust model indicates marginally that the certificate belongs to this recipient.");
    case UserID::Never:
        return i18n("This certificate should not be used.");
    case UserID::Undefined:
    case UserID::Unknown:
    default:
        return i18n("There is no indication that this certificate belongs to this recipient.");
    }
}

QString Formatting::validity(const KeyGroup &group)
{
    if (group.isNull()) {
        return QString();
    }

    const KeyGroup::Keys &keys = group.keys();
    if (keys.size() == 0) {
        return i18n("This group does not contain any keys.");
    }

    return getValidityStatement(keys);
}

namespace
{
template<typename Container>
UserID::Validity minimalValidity(const Container &keys)
{
    const int minValidity = std::accumulate(keys.cbegin(), keys.cend(), UserID::Ultimate + 1, [](int validity, const Key &key) {
        return std::min<int>(validity, minimalValidityOfNotRevokedUserIDs(key));
    });
    return minValidity <= UserID::Ultimate ? static_cast<UserID::Validity>(minValidity) : UserID::Unknown;
}

template<typename Container>
bool allKeysAreCompliant(const Container &keys)
{
    if (!DeVSCompliance::isActive()) {
        return true;
    }
    if (!DeVSCompliance::isCompliant()) {
        return false;
    }
    return Kleo::all_of(keys, DeVSCompliance::keyIsCompliant);
}
}

QIcon Formatting::validityIcon(const KeyGroup &group)
{
    if (Kleo::any_of(group.keys(), std::mem_fn(&Key::isBad))) {
        return Formatting::errorIcon();
    }
    return iconForValidityAndCompliance(minimalValidity(group.keys()), allKeysAreCompliant(group.keys()));
}

QString Formatting::complianceMode()
{
    const auto complianceValue = getCryptoConfigStringValue("gpg", "compliance");
    return complianceValue == QLatin1StringView("gnupg") ? QString() : complianceValue;
}

QString Formatting::complianceStringForKey(const GpgME::Key &key)
{
    // There will likely be more in the future for other institutions
    // for now we only have DE-VS
    if (DeVSCompliance::isCompliant()) {
        return isRemoteKey(key) //
            ? i18nc("@info the compliance of the key with certain requirements is unknown", "unknown")
            : DeVSCompliance::name(DeVSCompliance::keyIsCompliant(key));
    }
    return QString();
}

QString Formatting::complianceStringForUserID(const GpgME::UserID &userID)
{
    // There will likely be more in the future for other institutions
    // for now we only have DE-VS
    if (DeVSCompliance::isCompliant()) {
        return isRemoteKey(userID.parent()) //
            ? i18nc("@info the compliance of the key with certain requirements is unknown", "unknown")
            : DeVSCompliance::name(DeVSCompliance::userIDIsCompliant(userID));
    }
    return QString();
}

QString Formatting::complianceStringShort(const GpgME::UserID &id)
{
    if (DeVSCompliance::isCompliant() && DeVSCompliance::userIDIsCompliant(id)) {
        return QStringLiteral("★ ") + DeVSCompliance::name(true);
    }
    const bool keyValidityChecked = (id.parent().keyListMode() & GpgME::Validate);
    if (keyValidityChecked && id.validity() >= UserID::Full) {
        return i18nc("As in 'this user ID is valid.'", "certified");
    }
    if (id.parent().isDisabled()) {
        return i18n("disabled");
    }
    if (id.parent().isRevoked() || id.isRevoked()) {
        return i18n("revoked");
    }
    if (id.parent().isExpired() || isExpired(id)) {
        return i18n("expired");
    }
    if (id.parent().isInvalid() || id.isInvalid()) {
        return i18n("invalid");
    }
    if (keyValidityChecked) {
        return i18nc("As in 'this user ID is not certified'", "not certified");
    }

    return i18nc("The validity of this user ID has not been/could not be checked", "not checked");
}

QString Formatting::complianceStringShort(const GpgME::Key &key)
{
    if (DeVSCompliance::isCompliant() && DeVSCompliance::keyIsCompliant(key)) {
        return QStringLiteral("★ ") + DeVSCompliance::name(true);
    }
    const bool keyValidityChecked = (key.keyListMode() & GpgME::Validate);
    if (key.isDisabled()) {
        return i18n("disabled");
    }
    if (key.isRevoked()) {
        return i18n("revoked");
    }
    if (key.isExpired()) {
        return i18n("expired");
    }
    if (key.isInvalid()) {
        return i18n("invalid");
    }
    if (keyValidityChecked && Kleo::allUserIDsHaveFullValidity(key)) {
        return i18nc("As in all user IDs are valid.", "certified");
    }
    if (keyValidityChecked) {
        return i18nc("As in not all user IDs are valid.", "not certified");
    }

    return i18nc("The validity of the user IDs has not been/could not be checked", "not checked");
}

QString Formatting::complianceStringShort(const KeyGroup &group)
{
    const KeyGroup::Keys &keys = group.keys();

    const bool allKeysFullyValid = std::all_of(keys.cbegin(), keys.cend(), &Kleo::allUserIDsHaveFullValidity);
    if (allKeysFullyValid) {
        return i18nc("As in all keys are valid.", "all certified");
    }

    return i18nc("As in not all keys are valid.", "not all certified");
}

QString Formatting::prettyID(const char *id)
{
    if (!id) {
        return QString();
    }
    QString ret = QString::fromLatin1(id).toUpper();
    if (ret.size() == 64) {
        // looks like a V5 fingerprint; format the first 25 bytes as 10 groups of 5 hex characters
        ret.truncate(50);
        return ret.replace(QRegularExpression(QStringLiteral("(.....)")), QStringLiteral("\\1 ")).trimmed();
    }
    ret = ret.replace(QRegularExpression(QStringLiteral("(....)")), QStringLiteral("\\1 ")).trimmed();
    // For the standard 10 group V4 fingerprint let us use a double space in the
    // middle to increase readability
    if (ret.size() == 49) {
        ret.insert(24, QLatin1Char(' '));
    }
    return ret;
}

QString Formatting::accessibleHexID(const char *id)
{
    static const QRegularExpression groupOfFourRegExp{QStringLiteral("(?:(.)(.)(.)(.))")};
    static const QRegularExpression groupOfFiveRegExp{QStringLiteral("(?:(.)(.)(.)(.)(.))")};

    QString ret;
    ret = QString::fromLatin1(id);
    if (ret.size() == 64) {
        ret.truncate(50);
        return ret.replace(groupOfFiveRegExp, QStringLiteral("\\1 \\2 \\3 \\4 \\5, ")).chopped(2);
    }
    if (!ret.isEmpty() && (ret.size() % 4 == 0)) {
        ret = ret.replace(groupOfFourRegExp, QStringLiteral("\\1 \\2 \\3 \\4, ")).chopped(2);
    }
    return ret;
}

QString Formatting::origin(int o)
{
    switch (o) {
    case Key::OriginKS:
        return i18n("Keyserver");
    case Key::OriginDane:
        return QStringLiteral("DANE");
    case Key::OriginWKD:
        return QStringLiteral("WKD");
    case Key::OriginURL:
        return QStringLiteral("URL");
    case Key::OriginFile:
        return i18n("File import");
    case Key::OriginSelf:
        return i18n("Generated");
    case Key::OriginOther:
    case Key::OriginUnknown:
    default:
        return {};
    }
}

namespace
{
QString formatTrustScope(const char *trustScope)
{
    static const QRegularExpression escapedNonAlphaNum{QStringLiteral(R"(\\([^0-9A-Za-z]))")};

    const auto scopeRegExp = QString::fromUtf8(trustScope);
    if (scopeRegExp.startsWith(u"<[^>]+[@.]") && scopeRegExp.endsWith(u">$")) {
        // looks like a trust scope regular expression created by gpg
        auto domain = scopeRegExp.mid(10, scopeRegExp.size() - 10 - 2);
        domain.replace(escapedNonAlphaNum, QStringLiteral(R"(\1)"));
        return domain;
    }
    return scopeRegExp;
}
}

QString Formatting::trustSignatureDomain(const GpgME::UserID::Signature &sig)
{
    return formatTrustScope(sig.trustScope());
}

QString Formatting::trustSignature(const GpgME::UserID::Signature &sig)
{
    switch (sig.trustValue()) {
    case TrustSignatureTrust::Partial:
        return i18nc("Certifies this key as partially trusted introducer for 'domain name'.",
                     "Certifies this key as partially trusted introducer for '%1'.",
                     trustSignatureDomain(sig));
    case TrustSignatureTrust::Complete:
        return i18nc("Certifies this key as fully trusted introducer for 'domain name'.",
                     "Certifies this key as fully trusted introducer for '%1'.",
                     trustSignatureDomain(sig));
    default:
        return {};
    }
}

QString Formatting::errorAsString(const GpgME::Error &error)
{
#ifdef Q_OS_WIN
    // On Windows, we set GpgME resp. libgpg-error to return (translated) error messages as UTF-8
#if GPGMEPP_ERROR_HAS_ASSTDSTRING
    const std::string s = error.asStdString();
    qCDebug(LIBKLEO_LOG) << __func__ << "gettext_use_utf8(-1) returns" << gettext_use_utf8(-1);
    qCDebug(LIBKLEO_LOG) << __func__ << "error:" << s;
    qCDebug(LIBKLEO_LOG) << __func__ << "error (percent-encoded):" << QByteArray::fromStdString(s).toPercentEncoding();
    return QString::fromStdString(s);
#else
    const char *s = error.asString();
    qCDebug(LIBKLEO_LOG) << __func__ << "gettext_use_utf8(-1) returns" << gettext_use_utf8(-1);
    qCDebug(LIBKLEO_LOG) << __func__ << "error:" << s;
    qCDebug(LIBKLEO_LOG) << __func__ << "error (percent-encoded):" << QByteArray{s}.toPercentEncoding();
    return QString::fromUtf8(s);
#endif
#else
#if GPGMEPP_ERROR_HAS_ASSTDSTRING
    const std::string s = error.asStdString();
    return QString::fromLocal8Bit(QByteArrayView{s.data(), qsizetype(s.size())});
#else
    return QString::fromLocal8Bit(error.asString());
#endif
#endif
}

QString Formatting::prettyAlgorithmName(const std::string &algorithm)
{
    static const std::map<std::string, QString> displayNames = {
        {"brainpoolP256r1", i18nc("@info", "ECC (Brainpool P-256)")},
        {"brainpoolP384r1", i18nc("@info", "ECC (Brainpool P-384)")},
        {"brainpoolP512r1", i18nc("@info", "ECC (Brainpool P-512)")},
        {"curve25519", i18nc("@info", "ECC (Curve25519)")},
        {"curve448", i18nc("@info", "ECC (Curve448)")},
        {"ed25519", i18nc("@info", "ECC (Ed25519)")},
        {"ed448", i18nc("@info", "ECC (Ed448)")},
        {"cv25519", i18nc("@info", "ECC (Cv25519)")},
        {"cv448", i18nc("@info", "ECC (Cv448)")},
        {"nistp256", i18nc("@info", "ECC (NIST P-256)")},
        {"nistp384", i18nc("@info", "ECC (NIST P-384)")},
        {"nistp521", i18nc("@info", "ECC (NIST P-521)")},
        {"rsa1024", i18nc("@info", "RSA 1024")},
        {"rsa2048", i18nc("@info", "RSA 2048")},
        {"rsa3072", i18nc("@info", "RSA 3072")},
        {"rsa4096", i18nc("@info", "RSA 4096")},
        {"dsa1024", i18nc("@info", "DSA 1024")},
        {"dsa2048", i18nc("@info", "DSA 2048")},
        {"elg1024", i18nc("@info", "Elgamal 1024")},
        {"elg2048", i18nc("@info", "Elgamal 2048")},
        {"elg3072", i18nc("@info", "Elgamal 3072")},
        {"elg4096", i18nc("@info", "Elgamal 4096")},
        {"ky768_cv25519", i18nc("@info", "Kyber 768 (Curve25519)")},
        {"ky768_bp256", i18nc("@info", "Kyber 768 (Brainpool P-256)")},
        {"ky1024_bp384", i18nc("@info", "Kyber 1024 (Brainpool P-384)")},
        {"ky1024_cv448", i18nc("@info", "Kyber 1024 (Curve448)")},
    };
    const auto it = displayNames.find(algorithm);
    return (it != displayNames.end()) ? it->second : QString::fromStdString(algorithm);
}

static QString formatValidSignatureWithTrustLevel(const GpgME::UserID &id)
{
    if (id.isNull()) {
        return QString();
    }
    switch (id.validity()) {
    case GpgME::UserID::Marginal:
        return i18n("The signature is valid but the trust in the certificate's validity is only marginal.");
    case GpgME::UserID::Full:
        return i18n("The signature is valid and the certificate's validity is fully trusted.");
    case GpgME::UserID::Ultimate:
        return i18n("The signature is valid and the certificate's validity is ultimately trusted.");
    case GpgME::UserID::Never:
        return i18n("The signature is valid but the certificate's validity is <em>not trusted</em>.");
    case GpgME::UserID::Unknown:
        return i18n("The signature is valid but the certificate's validity is unknown.");
    case GpgME::UserID::Undefined:
    default:
        return i18n("The signature is valid but the certificate's validity is undefined.");
    }
}

static QString renderKeyLink(const QString &fpr, const QString &text)
{
    return QStringLiteral("<a href=\"key:%1\">%2</a>").arg(fpr, text.toHtmlEscaped());
}

static QString renderKey(const GpgME::Key &key)
{
    if (key.isNull()) {
        return i18n("Unknown certificate");
    }

    return renderKeyLink(QLatin1StringView(key.primaryFingerprint()),
                         i18nc("User ID (Key ID)", "%1 (%2)", Formatting::prettyNameAndEMail(key), Formatting::prettyID(key.subkey(0).keyID())));
}

static QString formatSigningInformation(const GpgME::Signature &sig, const GpgME::Key &key)
{
    if (sig.isNull()) {
        return QString();
    }
    QString text;
    const QDateTime dt = sig.creationTime() != 0 ? QDateTime::fromSecsSinceEpoch(quint32(sig.creationTime())) : QDateTime();

    if (key.isNull()) {
        const auto id =
            QStringLiteral("<br/><a href='certificate:%1'>%2</a>").arg(QString::fromLatin1(sig.fingerprint()), Formatting::prettyID(sig.fingerprint()));
        if (dt.isValid()) {
            return i18nc("1 is a date",
                         "Signature created on %1 using an unknown certificate with fingerprint %2",
                         QLocale().toString(dt, QLocale::ShortFormat),
                         id);
        }
        return i18n("Signature created using an unknown certificate with fingerprint %1", id);
    }

    if (dt.isValid()) {
        text += i18nc("1 is a date", "Signature created on %1 with certificate: %2", QLocale().toString(dt, QLocale::ShortFormat), renderKey(key));
    } else {
        text += i18n("Signature created with certificate: %1", renderKey(key));
    }

    if (Kleo::DeVSCompliance::isCompliant() && ((sig.summary() & GpgME::Signature::Valid) || (sig.summary() & GpgME::Signature::Green))) {
        text += (QStringLiteral("<br/>")
                 + (sig.isDeVs() ? i18nc("%1 is a placeholder for the name of a compliance mode. E.g. NATO RESTRICTED compliant or VS-NfD compliant",
                                         "The signature is %1",
                                         Kleo::DeVSCompliance::name(true))
                                 : i18nc("%1 is a placeholder for the name of a compliance mode. E.g. NATO RESTRICTED compliant or VS-NfD compliant",
                                         "The signature <b>is not</b> %1.",
                                         Kleo::DeVSCompliance::name(true))));
    }

    return text;
}

static QString signatureSummaryToString(GpgME::Signature::Summary summary)
{
    if (summary & GpgME::Signature::None) {
        return i18n("Error: Signature not verified");
    } else if ((summary & GpgME::Signature::Valid) || (summary & GpgME::Signature::Green)) {
        return i18n("Good signature");
    } else if (summary & GpgME::Signature::KeyRevoked) {
        return i18n("Signing certificate was revoked");
    } else if (summary & GpgME::Signature::KeyExpired) {
        return i18n("Signing certificate is expired");
    } else if (summary & GpgME::Signature::KeyMissing) {
        return i18n("Certificate is not available");
    } else if (summary & GpgME::Signature::SigExpired) {
        return i18n("Signature expired");
    } else if (summary & GpgME::Signature::CrlMissing) {
        return i18n("CRL missing");
    } else if (summary & GpgME::Signature::CrlTooOld) {
        return i18n("CRL too old");
    } else if (summary & GpgME::Signature::BadPolicy) {
        return i18n("Bad policy");
    } else if (summary & GpgME::Signature::SysError) {
        return i18n("System error"); // ### retrieve system error details?
    } else if (summary & GpgME::Signature::Red) {
        return i18n("Bad signature");
    }
    return QString();
}

static QLatin1StringView stripAngleBrackets(const QLatin1StringView &str)
{
    if (str.isEmpty()) {
        return str;
    }
    if (str[0] == '<' && str[str.size() - 1] == '>') {
        return str.mid(1, str.size() - 2);
    }
    return str;
}

QString Formatting::email(const GpgME::UserID &uid)
{
    if (uid.parent().protocol() == GpgME::OpenPGP) {
        const QLatin1StringView email(uid.email());
        if (!email.isEmpty()) {
            return stripAngleBrackets(email).toString();
        }
        return {};
    }

    Q_ASSERT(uid.parent().protocol() == GpgME::CMS);

    const QLatin1StringView id(uid.id());
    if (!id.isEmpty()) {
        if (id[0] == '<') {
            return stripAngleBrackets(id).toString();
        }
        return QGpgME::DN(id)[QStringLiteral("EMAIL")].trimmed();
    }
    return {};
}

static GpgME::UserID findUserIDByMailbox(const GpgME::Key &key, const QString &email)
{
    const auto userIDs{key.userIDs()};
    for (const GpgME::UserID &id : userIDs) {
        if (Formatting::email(id).compare(email, Qt::CaseInsensitive)) {
            return id;
        }
    }
    return {};
}

QString Kleo::Formatting::prettySignature(const GpgME::Signature &sig, const QString &sender)
{
    if (sig.isNull()) {
        return QString();
    }

    const GpgME::Key key = Kleo::KeyCache::instance()->findSigner(sig);

    const QString text = formatSigningInformation(sig, key) + QLatin1StringView("<br/>");

    // Green
    if (sig.summary() & GpgME::Signature::Valid) {
        GpgME::UserID id = findUserIDByMailbox(key, sender);
        if (id.isNull()) {
            for (int i = 0, count = key.userIDs().size(); i < count; i++) {
                id = key.userID(i);
                if (!id.isNull()) {
                    break;
                }
            }
        }

        return text + formatValidSignatureWithTrustLevel(!id.isNull() ? id : key.userID(0));
    }

    // Red
    if ((sig.summary() & GpgME::Signature::Red)) {
        const QString ret = text + i18n("The signature is invalid: %1", signatureSummaryToString(sig.summary()));
        if (sig.summary() & GpgME::Signature::SysError) {
            return ret + QStringLiteral(" (%1)").arg(Kleo::Formatting::errorAsString(sig.status()));
        }
        return ret;
    }

    // Key missing
    if ((sig.summary() & GpgME::Signature::KeyMissing)) {
        return text + i18n("You can search the certificate on a keyserver or import it from a file.");
    }

    // Yellow
    if ((sig.validity() & GpgME::Signature::Validity::Undefined) //
        || (sig.validity() & GpgME::Signature::Validity::Unknown) //
        || (sig.summary() == GpgME::Signature::Summary::None)) {
        return text
            + (key.protocol() == GpgME::OpenPGP
                   ? i18n("The used key is not certified by you or any trusted person.")
                   : i18n("The used certificate is not certified by a trustworthy Certificate Authority or the Certificate Authority is unknown."));
    }

    // Catch all fall through
    const QString ret = text + i18n("The signature is invalid: %1", signatureSummaryToString(sig.summary()));
    if (sig.summary() & GpgME::Signature::SysError) {
        return ret + QStringLiteral(" (%1)").arg(Kleo::Formatting::errorAsString(sig.status()));
    }
    return ret;
}
