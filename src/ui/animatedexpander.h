/*
    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2019, 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QWidget>

#include <memory>

class QLayout;
class QString;

// based on code from StackOverflow
class KLEO_EXPORT AnimatedExpander : public QWidget
{
    Q_OBJECT
public:
    explicit AnimatedExpander(const QString &title, const QString &accessibleTitle = {}, QWidget *parent = nullptr);
    ~AnimatedExpander() override;

    void setContentLayout(QLayout *contentLayout);

    bool isExpanded() const;
    void setExpanded(bool expanded);

    int contentHeight() const;
    int contentWidth() const;

Q_SIGNALS:
    void startExpanding();

private:
    class Private;
    const std::unique_ptr<Private> d;
};
