/*
    ui/readerportselection.h

    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QWidget>

namespace Kleo
{

class KLEO_EXPORT ReaderPortSelection : public QWidget
{
    Q_OBJECT
public:
    explicit ReaderPortSelection(QWidget *parent = nullptr);
    ~ReaderPortSelection() override;

    void setValue(const QString &value);
    [[nodiscard]] QString value() const;

Q_SIGNALS:
    void valueChanged(const QString &newValue);

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
