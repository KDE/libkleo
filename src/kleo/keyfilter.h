/*
    keyfilter.h

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QFlags>

#include <algorithm>

#include <kleo_export.h>

namespace GpgME
{
class Key;
}

class QFont;
class QColor;
class QString;

namespace Kleo
{

/**
   @short An abstract base class key filters

*/
class KLEO_EXPORT KeyFilter
{
public:
    virtual ~KeyFilter() {}

    enum MatchContext {
        NoMatchContext = 0x0,
        Appearance = 0x1,
        Filtering = 0x2,

        AnyMatchContext = Appearance | Filtering
    };
    Q_DECLARE_FLAGS(MatchContexts, MatchContext)

    virtual bool matches(const GpgME::Key &key, MatchContexts ctx) const = 0;

    virtual unsigned int specificity() const = 0;
    virtual QString id() const = 0;
    virtual MatchContexts availableMatchContexts() const = 0;

    // not sure if we want these here, but for the time being, it's
    // the easiest way:
    virtual QColor fgColor() const = 0;
    virtual QColor bgColor() const = 0;
    virtual QString name() const = 0;
    virtual QString icon() const = 0;

    class FontDescription
    {
    public:
        FontDescription();
        FontDescription(const FontDescription &other);
        FontDescription &operator=(const FontDescription &other)
        {
            FontDescription copy(other);
            swap(copy);
            return *this;
        }
        ~FontDescription();

        static FontDescription create(bool bold, bool italic, bool strikeOut);
        static FontDescription create(const QFont &font, bool bold, bool italic, bool strikeOut);

        QFont font(const QFont &base) const;

        FontDescription resolve(const FontDescription &other) const;

        void swap(FontDescription &other)
        {
            std::swap(this->d, other.d);
        }
        struct Private;
    private:
        Private *d;
    };

    virtual FontDescription fontDescription() const = 0;
};

Q_DECLARE_OPERATORS_FOR_FLAGS(KeyFilter::MatchContexts)

}

#include <QObject>

Q_DECLARE_METATYPE(Kleo::KeyFilter::MatchContexts)
