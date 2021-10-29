/*
    ui/cryptoconfigentryreaderport.cpp

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "cryptoconfigentryreaderport_p.h"

#include "cryptoconfigmodule.h"

#include "utils/scdaemon.h"

#include <KLocalizedString>

#include <QGpgME/CryptoConfig>
#if __has_include(<QGpgME/Debug>)
# include <QGpgME/Debug>
#endif

#include <QComboBox>
#include <QGridLayout>
#include <QLabel>

#include <gpgme++/error.h>

#include <libkleo_debug.h>

namespace Kleo
{

CryptoConfigEntryReaderPort::CryptoConfigEntryReaderPort(CryptoConfigModule *module,
                                                         QGpgME::CryptoConfigEntry *entry,
                                                         const QString &entryName,
                                                         QGridLayout *layout,
                                                         QWidget *parent)
    : CryptoConfigEntryGUI{module, entry, entryName}
    , mComboBox{new QComboBox{parent}}
    , mCustomEntryPlaceholderText{i18nc("@item:inlistbox", "Custom entry")}
{
    auto const label = new QLabel{i18nc("@label:listbox Reader for smart cards",
                                        "Reader to connect to"), parent};
    label->setBuddy(mComboBox);

    mComboBox->addItem(i18nc("@item:inlistbox", "Default reader"));

    GpgME::Error err;
    const auto readers = SCDaemon::getReaders(err);
    if (err) {
        qCWarning(LIBKLEO_LOG) << "Getting available smart card readers failed:" << err;
    } else {
        std::for_each(std::begin(readers), std::end(readers),
                      [this](const auto &reader) {
                          mComboBox->addItem(QString::fromStdString(reader));
                      });
    }

    mComboBox->addItem(mCustomEntryPlaceholderText);
    mComboBox->setToolTip(xi18nc("@info:tooltip",
                                 "<para>Select the smart card reader that GnuPG shall use.<list>"
                                 "<item>The first item will make GnuPG use the first reader that is found.</item>"
                                 "<item>The last item allows you to enter a custom reader ID or reader port number.</item>"
                                 "<item>All other items represent readers that were found by GnuPG.</item>"
                                 "</list></para>"));

    if (entry->isReadOnly()) {
        label->setEnabled(false);
        mComboBox->setEnabled(false);
    } else {
        connect(mComboBox, qOverload<int>(&QComboBox::currentIndexChanged),
                this, &CryptoConfigEntryReaderPort::slotChanged);
        connect(mComboBox, qOverload<int>(&QComboBox::currentIndexChanged),
                this, &CryptoConfigEntryReaderPort::onCurrentIndexChanged);
        connect(mComboBox, &QComboBox::editTextChanged,
                this, &CryptoConfigEntryReaderPort::slotChanged);
        connect(mComboBox, &QComboBox::editTextChanged,
                this, &CryptoConfigEntryReaderPort::onEditTextChanged);
    }

    const int row = layout->rowCount();
    layout->addWidget(label, row, 1);
    layout->addWidget(mComboBox, row, 2);
}

void CryptoConfigEntryReaderPort::doSave()
{
    if (mEntry->isReadOnly()) {
        return;
    }
    const int index = mComboBox->currentIndex();
    if (index == 0) {
        mEntry->setStringValue({});
    } else if (mComboBox->currentText() != mCustomEntryPlaceholderText) {
        mEntry->setStringValue(mComboBox->currentText());
    }
}

void CryptoConfigEntryReaderPort::doLoad()
{
    const QString s = mEntry->stringValue();
    if (s.isEmpty()) {
        mComboBox->setCurrentIndex(0);
        return;
    }
    for (int i = 1; i < mComboBox->count() - 1; ++i) {
        if (s == mComboBox->itemText(i)) {
            mComboBox->setCurrentIndex(i);
            return;
        }
    }
    mComboBox->setCurrentIndex(mComboBox->count() - 1);
    mComboBox->setEditText(s);
}

void CryptoConfigEntryReaderPort::onCurrentIndexChanged(int index)
{
    // the last item serves as input for a custom entry
    mComboBox->setEditable(index == mComboBox->count() - 1);
}

void CryptoConfigEntryReaderPort::onEditTextChanged(const QString &text)
{
    const int lastIndex = mComboBox->count() - 1;
    // do not overwrite the text of the custom item with the text of another item
    if (mComboBox->currentIndex() == lastIndex) {
        mComboBox->setItemText(lastIndex, text);
    }
}

} // namespace Kleo
