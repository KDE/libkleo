/*
    kleo/debug.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "debug.h"

#include "keygroup.h"

#include <QDebug>

QDebug operator<<(QDebug debug, const Kleo::KeyGroup &group)
{
    const bool oldSetting = debug.autoInsertSpaces();
    if (group.isNull()) {
        debug << "Null";
    } else {
        debug.nospace() << group.name() << " (id: " << group.id() << ", source: " << group.source()
            << ", keys: " << group.keys().size() << ", isImmutable: " << group.isImmutable() << ")";
    }
    debug.setAutoInsertSpaces(oldSetting);
    return debug.maybeSpace();
}
