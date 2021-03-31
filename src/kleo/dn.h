/*
    dn.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QString>
#include <QVector>

#include <QStringList>
class QWidget;

namespace Kleo
{
class DNAttributeOrderConfigWidget;
}

namespace Kleo
{

/**
   @short DN Attribute mapper
*/
class KLEO_EXPORT DNAttributeMapper
{
    DNAttributeMapper();
    ~DNAttributeMapper();
public:
    static const DNAttributeMapper *instance();

    QString name2label(const QString &s) const;
    QStringList names() const;

    const QStringList &attributeOrder() const;

    void setAttributeOrder(const QStringList &order);

    DNAttributeOrderConfigWidget *configWidget(QWidget *parent = nullptr) const;

private:
    class Private;
    Private *d;
    static DNAttributeMapper *mSelf;
};

/**
   @short DN parser and reorderer
*/
class KLEO_EXPORT DN
{
public:
    class Attribute;
    using AttributeList = QVector<Attribute>;
    using const_iterator = AttributeList::const_iterator;

    DN();
    explicit DN(const QString &dn);
    explicit DN(const char *utf8DN);
    DN(const DN &other);
    ~DN();

    const DN &operator=(const DN &other);

    /** @return the value in rfc-2253-escaped form */
    static QString escape(const QString &value);

    /** @return the DN in a reordered form, according to the settings in
        the [DN] group of the application's config file */
    QString prettyDN() const;
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
        : mName(name.toUpper()), mValue(value) {}
    Attribute(const Attribute &other)
        : mName(other.name()), mValue(other.value()) {}

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

