/*
    dn.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    DN parsing:
    SPDX-FileCopyrightText: 2002 g10 Code GmbH
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "dn.h"
#include "libkleo_debug.h"

#include "oidmap.h"

#include <algorithm>

#ifdef _MSC_VER
#include <string.h>
#define strcasecmp _stricmp
#endif

class Kleo::DN::Private
{
public:
    Private()
        : mRefCount(0)
    {
    }
    Private(const Private &other)
        : attributes(other.attributes)
        , reorderedAttributes(other.reorderedAttributes)
        , mRefCount(0)
    {
    }

    int ref()
    {
        return ++mRefCount;
    }

    int unref()
    {
        if (--mRefCount <= 0) {
            delete this;
            return 0;
        } else {
            return mRefCount;
        }
    }

    int refCount() const
    {
        return mRefCount;
    }

    DN::Attribute::List attributes;
    DN::Attribute::List reorderedAttributes;

private:
    int mRefCount;
};

namespace
{
struct DnPair {
    char *key;
    char *value;
};
}

// copied from CryptPlug and adapted to work on DN::Attribute::List:

#define digitp(p) (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) (digitp(a) || (*(a) >= 'A' && *(a) <= 'F') || (*(a) >= 'a' && *(a) <= 'f'))
#define xtoi_1(p) (*(p) <= '9' ? (*(p) - '0') : *(p) <= 'F' ? (*(p) - 'A' + 10) : (*(p) - 'a' + 10))
#define xtoi_2(p) ((xtoi_1(p) * 16) + xtoi_1((p) + 1))

static char *trim_trailing_spaces(char *string)
{
    char *p;
    char *mark;

    for (mark = nullptr, p = string; *p; p++) {
        if (isspace(*p)) {
            if (!mark) {
                mark = p;
            }
        } else {
            mark = nullptr;
        }
    }
    if (mark) {
        *mark = '\0';
    }

    return string;
}

/* Parse a DN and return an array-ized one.  This is not a validating
   parser and it does not support any old-stylish syntax; gpgme is
   expected to return only rfc2253 compatible strings. */
static const unsigned char *parse_dn_part(DnPair *array, const unsigned char *string)
{
    const unsigned char *s;
    const unsigned char *s1;
    size_t n;
    char *p;

    /* parse attributeType */
    for (s = string + 1; *s && *s != '='; s++) {
        ;
    }
    if (!*s) {
        return nullptr; /* error */
    }
    n = s - string;
    if (!n) {
        return nullptr; /* empty key */
    }
    p = (char *)malloc(n + 1);

    memcpy(p, string, n);
    p[n] = 0;
    trim_trailing_spaces((char *)p);
    // map OIDs to their names:
    if (const char *name = Kleo::attributeNameForOID(p)) {
        free(p);
        p = strdup(name);
    }
    array->key = p;
    string = s + 1;

    if (*string == '#') {
        /* hexstring */
        string++;
        for (s = string; hexdigitp(s); s++)
            ;
        n = s - string;
        if (!n || (n & 1)) {
            return nullptr; /* empty or odd number of digits */
        }
        n /= 2;
        array->value = p = (char *)malloc(n + 1);

        for (s1 = string; n; s1 += 2, n--) {
            *p++ = xtoi_2(s1);
        }
        *p = 0;
    } else {
        /* regular v3 quoted string */
        for (n = 0, s = string; *s; s++) {
            if (*s == '\\') {
                /* pair */
                s++;
                if (*s == ',' || *s == '=' || *s == '+' || *s == '<' || *s == '>' || *s == '#' || *s == ';' || *s == '\\' || *s == '\"' || *s == ' ') {
                    n++;
                } else if (hexdigitp(s) && hexdigitp(s + 1)) {
                    s++;
                    n++;
                } else {
                    return nullptr; /* invalid escape sequence */
                }
            } else if (*s == '\"') {
                return nullptr; /* invalid encoding */
            } else if (*s == ',' || *s == '=' || *s == '+' || *s == '<' || *s == '>' || *s == '#' || *s == ';') {
                break;
            } else {
                n++;
            }
        }

        array->value = p = (char *)malloc(n + 1);

        for (s = string; n; s++, n--) {
            if (*s == '\\') {
                s++;
                if (hexdigitp(s)) {
                    *p++ = xtoi_2(s);
                    s++;
                } else {
                    *p++ = *s;
                }
            } else {
                *p++ = *s;
            }
        }
        *p = 0;
    }
    return s;
}

/* Parse a DN and return an array-ized one.  This is not a validating
   parser and it does not support any old-stylish syntax; gpgme is
   expected to return only rfc2253 compatible strings. */
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
static Kleo::DN::Attribute::List parse_dn(const unsigned char *string)
{
    QT_WARNING_POP
    if (!string) {
        QT_WARNING_PUSH
        QT_WARNING_DISABLE_DEPRECATED
        return QList<Kleo::DN::Attribute>();
        QT_WARNING_POP
    }

    QT_WARNING_PUSH
    QT_WARNING_DISABLE_DEPRECATED
    QList<Kleo::DN::Attribute> result;
    QT_WARNING_POP
    while (*string) {
        while (*string == ' ') {
            string++;
        }
        if (!*string) {
            break; /* ready */
        }

        DnPair pair = {nullptr, nullptr};
        string = parse_dn_part(&pair, string);
        if (!string) {
            goto failure;
        }
        if (pair.key && pair.value) {
            QT_WARNING_PUSH
            QT_WARNING_DISABLE_DEPRECATED
            result.push_back(Kleo::DN::Attribute(QString::fromUtf8(pair.key), QString::fromUtf8(pair.value)));
            QT_WARNING_POP
        }
        free(pair.key);
        free(pair.value);

        while (*string == ' ') {
            string++;
        }
        if (*string && *string != ',' && *string != ';' && *string != '+') {
            goto failure; /* invalid delimiter */
        }
        if (*string) {
            string++;
        }
    }
    return result;

failure:
    QT_WARNING_PUSH
    QT_WARNING_DISABLE_DEPRECATED
    return QList<Kleo::DN::Attribute>();
    QT_WARNING_POP
}

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
static QList<Kleo::DN::Attribute> parse_dn(const QString &dn)
{
    QT_WARNING_POP
    return parse_dn((const unsigned char *)dn.toUtf8().data());
}

static QString dn_escape(const QString &s)
{
    QString result;
    for (int i = 0, end = s.length(); i != end; ++i) {
        const QChar ch = s[i];
        switch (ch.unicode()) {
        case ',':
        case '+':
        case '"':
        case '\\':
        case '<':
        case '>':
        case ';':
            result += QLatin1Char('\\');
            // fall through
            [[fallthrough]];
        default:
            result += ch;
        }
    }
    return result;
}

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
static QStringList listAttributes(const QList<Kleo::DN::Attribute> &dn)
{
    QT_WARNING_POP
    QStringList result;
    result.reserve(dn.size());
    for (const auto &attribute : dn) {
        if (!attribute.name().isEmpty() && !attribute.value().isEmpty()) {
            result.push_back(attribute.name().trimmed() + QLatin1Char('=') + dn_escape(attribute.value().trimmed()));
        }
    }
    return result;
}

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
static QString serialise(const QList<Kleo::DN::Attribute> &dn, const QString &sep)
{
    QT_WARNING_POP
    return listAttributes(dn).join(sep);
}

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
static Kleo::DN::Attribute::List reorder_dn(const Kleo::DN::Attribute::List &dn)
{
    QT_WARNING_POP
    const QStringList &attrOrder = Kleo::DNAttributes::order();

    QT_WARNING_PUSH
    QT_WARNING_DISABLE_DEPRECATED
    Kleo::DN::Attribute::List unknownEntries;
    Kleo::DN::Attribute::List result;
    QT_WARNING_POP
    unknownEntries.reserve(dn.size());
    result.reserve(dn.size());

    // find all unknown entries in their order of appearance
    QT_WARNING_PUSH
    QT_WARNING_DISABLE_DEPRECATED
    for (Kleo::DN::const_iterator it = dn.begin(); it != dn.end(); ++it) {
        QT_WARNING_POP
        if (!attrOrder.contains((*it).name())) {
            unknownEntries.push_back(*it);
        }
    }

    // process the known attrs in the desired order
    for (QStringList::const_iterator oit = attrOrder.begin(); oit != attrOrder.end(); ++oit) {
        if (*oit == QLatin1StringView("_X_")) {
            // insert the unknown attrs
            std::copy(unknownEntries.begin(), unknownEntries.end(), std::back_inserter(result));
            unknownEntries.clear(); // don't produce dup's
        } else {
            QT_WARNING_PUSH
            QT_WARNING_DISABLE_DEPRECATED
            for (Kleo::DN::const_iterator dnit = dn.begin(); dnit != dn.end(); ++dnit) {
                QT_WARNING_POP
                if ((*dnit).name() == *oit) {
                    result.push_back(*dnit);
                }
            }
        }
    }

    return result;
}

//
//
// class DN
//
//

Kleo::DN::DN()
{
    d = new Private();
    d->ref();
}

Kleo::DN::DN(const QString &dn)
{
    d = new Private();
    d->ref();
    d->attributes = parse_dn(dn);
}

Kleo::DN::DN(const char *utf8DN)
{
    d = new Private();
    d->ref();
    if (utf8DN) {
        d->attributes = parse_dn((const unsigned char *)utf8DN);
    }
}

Kleo::DN::DN(const DN &other)
    : d(other.d)
{
    if (d) {
        d->ref();
    }
}

Kleo::DN::~DN()
{
    if (d) {
        d->unref();
    }
}

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
const Kleo::DN &Kleo::DN::operator=(const DN &that)
{
    QT_WARNING_POP
    if (this->d == that.d) {
        return *this;
    }

    if (that.d) {
        that.d->ref();
    }
    if (this->d) {
        this->d->unref();
    }

    this->d = that.d;

    return *this;
}

QString Kleo::DN::prettyDN() const
{
    if (!d) {
        return QString();
    }
    if (d->reorderedAttributes.empty()) {
        d->reorderedAttributes = reorder_dn(d->attributes);
    }
    return serialise(d->reorderedAttributes, QStringLiteral(","));
}

QStringList Kleo::DN::prettyAttributes() const
{
    if (!d) {
        return {};
    }

    if (d->reorderedAttributes.empty()) {
        d->reorderedAttributes = reorder_dn(d->attributes);
    }
    return listAttributes(d->reorderedAttributes);
}

QString Kleo::DN::dn() const
{
    return d ? serialise(d->attributes, QStringLiteral(",")) : QString();
}

QString Kleo::DN::dn(const QString &sep) const
{
    return d ? serialise(d->attributes, sep) : QString();
}

// static
QString Kleo::DN::escape(const QString &value)
{
    return dn_escape(value);
}

void Kleo::DN::detach()
{
    if (!d) {
        d = new Kleo::DN::Private();
        d->ref();
    } else if (d->refCount() > 1) {
        Kleo::DN::Private *d_save = d;
        d = new Kleo::DN::Private(*d);
        d->ref();
        d_save->unref();
    }
}

void Kleo::DN::append(const Attribute &attr)
{
    detach();
    d->attributes.push_back(attr);
    d->reorderedAttributes.clear();
}

QString Kleo::DN::operator[](const QString &attr) const
{
    if (!d) {
        return QString();
    }
    const QString attrUpper = attr.toUpper();
    for (QList<Attribute>::const_iterator it = d->attributes.constBegin(); it != d->attributes.constEnd(); ++it) {
        if ((*it).name() == attrUpper) {
            return (*it).value();
        }
    }
    return QString();
}

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
static QList<Kleo::DN::Attribute> empty;
QT_WARNING_POP

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
Kleo::DN::const_iterator Kleo::DN::begin() const
{
    QT_WARNING_POP
    return d ? d->attributes.constBegin() : empty.constBegin();
}

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
Kleo::DN::const_iterator Kleo::DN::end() const
{
    QT_WARNING_POP
    return d ? d->attributes.constEnd() : empty.constEnd();
}
