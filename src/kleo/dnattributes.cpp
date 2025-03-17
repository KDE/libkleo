/*
    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "dnattributes.h"

#include <libkleo_debug.h>

#include <KLazyLocalizedString>

#include <QMap>

namespace
{
static const QStringList defaultOrder = {
    QStringLiteral("CN"),
    QStringLiteral("L"),
    QStringLiteral("_X_"),
    QStringLiteral("OU"),
    QStringLiteral("O"),
    QStringLiteral("C"),
};

class DNAttributeOrderStore
{
    DNAttributeOrderStore()
        : mAttributeOrder{defaultOrder}
    {
    }

public:
    static DNAttributeOrderStore *instance()
    {
        static DNAttributeOrderStore *self = new DNAttributeOrderStore();
        return self;
    }

    const QStringList &attributeOrder() const
    {
        return mAttributeOrder.empty() ? defaultOrder : mAttributeOrder;
    }

    void setAttributeOrder(const QStringList &order)
    {
        mAttributeOrder = order;
    }

private:
    QStringList mAttributeOrder;
};
}

namespace
{
static const QMap<QString, KLazyLocalizedString> attributeNamesAndLabels = {
    // clang-format off
    {QStringLiteral("CN"),     kli18n("Common name")        },
    {QStringLiteral("SN"),     kli18n("Surname")            },
    {QStringLiteral("GN"),     kli18n("Given name")         },
    {QStringLiteral("L"),      kli18n("Location")           },
    {QStringLiteral("T"),      kli18n("Title")              },
    {QStringLiteral("OU"),     kli18n("Organizational unit")},
    {QStringLiteral("O"),      kli18n("Organization")       },
    {QStringLiteral("PC"),     kli18n("Postal code")        },
    {QStringLiteral("C"),      kli18n("Country code")       },
    {QStringLiteral("SP"),     kli18n("State or province")  },
    {QStringLiteral("DC"),     kli18n("Domain component")   },
    {QStringLiteral("BC"),     kli18n("Business category")  },
    {QStringLiteral("EMAIL"),  kli18n("Email address")      },
    {QStringLiteral("MAIL"),   kli18n("Mail address")       },
    {QStringLiteral("MOBILE"), kli18n("Mobile phone number")},
    {QStringLiteral("TEL"),    kli18n("Telephone number")   },
    {QStringLiteral("FAX"),    kli18n("Fax number")         },
    {QStringLiteral("STREET"), kli18n("Street address")     },
    {QStringLiteral("UID"),    kli18n("Unique ID")          },
    // clang-format on
};
}

// static
QStringList Kleo::DNAttributes::order()
{
    return DNAttributeOrderStore::instance()->attributeOrder();
}

// static
void Kleo::DNAttributes::setOrder(const QStringList &order)
{
    DNAttributeOrderStore::instance()->setAttributeOrder(order);
}

// static
QStringList Kleo::DNAttributes::defaultOrder()
{
    return ::defaultOrder;
}

QStringList Kleo::DNAttributes::names()
{
    return attributeNamesAndLabels.keys();
}

QString Kleo::DNAttributes::nameToLabel(const QString &name)
{
    const QString key{name.trimmed().toUpper()};
    if (DNAttributes::names().contains(key)) {
        return attributeNamesAndLabels.value(key).toString();
    }
    qCWarning(LIBKLEO_LOG) << "Attribute " << key << " doesn't exit. Bug ?";
    return {};
}
