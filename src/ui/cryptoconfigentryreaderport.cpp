/*
    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "cryptoconfigentryreaderport_p.h"

#include "cryptoconfigmodule.h"
#include "readerportselection.h"

#include <libkleo/scdaemon.h>

#include <libkleo_debug.h>

#include <KLocalizedString>

#include <QGpgME/CryptoConfig>
#if __has_include(<QGpgME/Debug>)
#include <QGpgME/Debug>
#endif

#include <QGridLayout>
#include <QLabel>

#include <gpgme++/error.h>

namespace Kleo
{

CryptoConfigEntryReaderPort::CryptoConfigEntryReaderPort(CryptoConfigModule *module,
                                                         QGpgME::CryptoConfigEntry *entry,
                                                         const QString &entryName,
                                                         QGridLayout *layout,
                                                         QWidget *parent)
    : CryptoConfigEntryGUI{module, entry, entryName}
    , mReaderPort{new ReaderPortSelection{parent}}
{
    auto const label = new QLabel{i18nc("@label:listbox Reader for smart cards", "Reader to connect to"), parent};
    label->setBuddy(mReaderPort);

    if (entry->isReadOnly()) {
        label->setEnabled(false);
        mReaderPort->setEnabled(false);
    } else {
        connect(mReaderPort, &ReaderPortSelection::valueChanged, this, &CryptoConfigEntryReaderPort::slotChanged);
    }

    const int row = layout->rowCount();
    layout->addWidget(label, row, 1);
    layout->addWidget(mReaderPort, row, 2);
}

void CryptoConfigEntryReaderPort::doSave()
{
    if (mEntry->isReadOnly()) {
        return;
    }
    mEntry->setStringValue(mReaderPort->value());
}

void CryptoConfigEntryReaderPort::doLoad()
{
    mReaderPort->setValue(mEntry->stringValue());
}

} // namespace Kleo

#include "moc_cryptoconfigentryreaderport_p.cpp"
