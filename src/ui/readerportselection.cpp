/*
    ui/readerportselection.cpp

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "readerportselection.h"

#include <utils/scdaemon.h>

#include <libkleo_debug.h>

#include <KLocalizedString>

#if __has_include(<QGpgME/Debug>)
#include <QGpgME/Debug>
#endif

#include <QComboBox>
#include <QHBoxLayout>
#include <QLineEdit>

#include <gpgme++/error.h>

using namespace Kleo;

class ReaderPortSelection::Private
{
public:
    Private(ReaderPortSelection *q);

    void setValue(const QString &value);
    QString value() const;

private:
    void onCurrentIndexChanged(int);
    void onEditTextChanged(const QString &);

private:
    ReaderPortSelection *const q = nullptr;
    QComboBox *const mComboBox = nullptr;
};

ReaderPortSelection::Private::Private(Kleo::ReaderPortSelection *qq)
    : q{qq}
    , mComboBox{new QComboBox{qq}}
{
    auto layout = new QHBoxLayout{q};
    layout->setContentsMargins({});
    layout->addWidget(mComboBox);

    mComboBox->addItem(i18nc("@item:inlistbox", "Default reader"), {});

    GpgME::Error err;
    const auto readers = SCDaemon::getReaders(err);
    if (err) {
        qCWarning(LIBKLEO_LOG) << "Getting available smart card readers failed:" << err;
    } else {
        std::for_each(std::begin(readers), std::end(readers), [this](const auto &reader) {
            const auto readerId = QString::fromStdString(reader);
            mComboBox->addItem(readerId, readerId);
        });
    }

    mComboBox->addItem(QString{}, {});
    mComboBox->setToolTip(xi18nc("@info:tooltip",
                                 "<para>Select the smart card reader that GnuPG shall use.<list>"
                                 "<item>The first item will make GnuPG use the first reader that is found.</item>"
                                 "<item>The last item allows you to enter a custom reader ID or reader port number.</item>"
                                 "<item>All other items represent readers that were found by GnuPG.</item>"
                                 "</list></para>"));

    connect(mComboBox, qOverload<int>(&QComboBox::currentIndexChanged), q, [this](int index) {
        onCurrentIndexChanged(index);
        Q_EMIT q->valueChanged(q->value());
    });
    connect(mComboBox, &QComboBox::editTextChanged, q, [this](const QString &text) {
        onEditTextChanged(text);
        Q_EMIT q->valueChanged(q->value());
    });
}

void ReaderPortSelection::Private::setValue(const QString &value)
{
    if (value.isEmpty()) {
        mComboBox->setCurrentIndex(0);
        return;
    }
    const int indexOfValue = mComboBox->findData(value);
    if (indexOfValue != -1) {
        mComboBox->setCurrentIndex(indexOfValue);
    } else {
        mComboBox->setCurrentIndex(mComboBox->count() - 1);
        mComboBox->setEditText(value);
    }
}

QString ReaderPortSelection::Private::value() const
{
    return mComboBox->currentData().toString();
}

void ReaderPortSelection::Private::onCurrentIndexChanged(int index)
{
    // the last item serves as input for a custom entry
    mComboBox->setEditable(index == mComboBox->count() - 1);
    if (mComboBox->lineEdit()) {
        mComboBox->lineEdit()->setPlaceholderText(i18nc("@item:inlistbox", "Custom reader ID or port number"));
    }
}

void ReaderPortSelection::Private::onEditTextChanged(const QString &text)
{
    const int lastIndex = mComboBox->count() - 1;
    // do not overwrite the text of the custom item with the text of another item
    if (mComboBox->currentIndex() == lastIndex) {
        mComboBox->setItemText(lastIndex, text);
        mComboBox->setItemData(lastIndex, text);
    }
}

ReaderPortSelection::ReaderPortSelection(QWidget *parent)
    : QWidget{parent}
    , d{new Private{this}}
{
}

ReaderPortSelection::~ReaderPortSelection() = default;

void ReaderPortSelection::setValue(const QString &value)
{
    d->setValue(value);
}

QString ReaderPortSelection::value() const
{
    return d->value();
}
