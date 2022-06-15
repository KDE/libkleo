/*
    kleo/debug.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2021, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "debug.h"

#include "keygroup.h"

#include <utils/formatting.h>

#include <QDebug>

using namespace Kleo;

QDebug operator<<(QDebug debug, const GpgME::Key &key)
{
    const bool oldSetting = debug.autoInsertSpaces();
    debug.nospace() << "GpgME::Key(";
    if (key.isNull()) {
        debug << "null";
    } else if (key.primaryFingerprint()) {
        debug << Formatting::summaryLine(key) << ", fpr: " << key.primaryFingerprint();
    } else {
        debug << Formatting::summaryLine(key) << ", id: " << key.keyID();
    }
    debug << ')';
    debug.setAutoInsertSpaces(oldSetting);
    return debug.maybeSpace();
}

QDebug operator<<(QDebug debug, const Kleo::KeyGroup &group)
{
    const bool oldSetting = debug.autoInsertSpaces();
    if (group.isNull()) {
        debug << "Null";
    } else {
        debug.nospace() << group.name() << " (id: " << group.id() << ", source: " << group.source() << ", keys: " << group.keys().size()
                        << ", isImmutable: " << group.isImmutable() << ")";
    }
    debug.setAutoInsertSpaces(oldSetting);
    return debug.maybeSpace();
}
