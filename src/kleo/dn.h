/*
    dn.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QList>
#include <QString>
#include <QStringList>

namespace Kleo
{

/**
   @short DN parser and reorderer
*/
class KLEO_EXPORT DN
{
public:
    class Attribute;
    using AttributeList = QList<Attribute>;
    using const_iterator = AttributeList::const_iterator;

    DN();
    explicit DN(const QString &dn);
    explicit DN(const char *utf8DN);
    DN(const DN &other);
    ~DN();

    const DN &operator=(const DN &other);

    static QStringList attributeOrder();
    static void setAttributeOrder(const QStringList &order);

    static QStringList defaultAttributeOrder();

    static QStringList attributeNames();
    static QString attributeNameToLabel(const QString &name);

    /** @return the value in rfc-2253-escaped form */
    static QString escape(const QString &value);

    /** @return the DN in a reordered form, according to the settings in
        the [DN] group of the application's config file */
    QString prettyDN() const;

    /** Returns the non-empty attributes formatted as \c{NAME=value} and reordered
     *  according to the settings in the [DN] group of the application's config file.
     */
    QStringList prettyAttributes() const;

    /** @return the DN in the original form */
    QString dn() const;
    /**
       \overload
       Uses \a sep as separator (default: ,)
    */
    QString dn(const QString &sep) const;

    QString operator[](const QString &attr) const;

    void append(const Attribute &attr);

    const_iterator begin() const;
    const_iterator end() const;

private:
    void detach();

private:
    class Private;
    Private *d;
};

class KLEO_EXPORT DN::Attribute
{
public:
    using List = DN::AttributeList;

    explicit Attribute(const QString &name = QString(), const QString &value = QString())
        : mName(name.toUpper())
        , mValue(value)
    {
    }
    Attribute(const Attribute &other)
        : mName(other.name())
        , mValue(other.value())
    {
    }

    const Attribute &operator=(const Attribute &other)
    {
        if (this != &other) {
            mName = other.name();
            mValue = other.value();
        }
        return *this;
    }

    const QString &name() const
    {
        return mName;
    }
    const QString &value() const
    {
        return mValue;
    }

    void setValue(const QString &value)
    {
        mValue = value;
    }

private:
    QString mName;
    QString mValue;
};

}
