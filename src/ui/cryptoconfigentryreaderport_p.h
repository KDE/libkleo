/*
    ui/cryptoconfigentryreaderport_p.h

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "cryptoconfigmodule_p.h"

namespace Kleo
{
class CryptoConfigModule;
class ReaderPortSelection;

/**
 * A widget manager for the reader-port entry of scdaemon in the crypto config
 */
class CryptoConfigEntryReaderPort : public CryptoConfigEntryGUI
{
    Q_OBJECT
public:
    CryptoConfigEntryReaderPort(CryptoConfigModule *module,
                                QGpgME::CryptoConfigEntry *entry,
                                const QString &entryName,
                                QGridLayout *layout,
                                QWidget *parent = nullptr);

private:
    void doSave() override;
    void doLoad() override;

private:
    ReaderPortSelection *const mReaderPort = nullptr;
};

}
