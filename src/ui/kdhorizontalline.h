/* -*- Mode: C++ -*-
   KD Tools - a set of useful widgets for Qt
*/

/****************************************************************************
** SPDX-FileCopyrightText: 2005 Klarälvdalens Datakonsult AB. All rights reserved.
**
** This file is part of the KD Tools library.
**
** SPDX-License-Identifier: GPL-2.0-or-later
**
** Licensees holding valid commercial KD Tools licenses may use this file in
** accordance with the KD Tools Commercial License Agreement provided with
** the Software.
**
** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
**
** See http://www.klaralvdalens-datakonsult.se/?page=products for
**   information about KD Tools Commercial License Agreements.
**
** Contact info@klaralvdalens-datakonsult.se if any conditions of this
** licensing are not clear to you.
**
**********************************************************************/

#ifndef __KDTOOLS__KDHORIZONTALLINE_H__
#define __KDTOOLS__KDHORIZONTALLINE_H__

#include "kleo_export.h"

#include <QFrame>

class KLEO_EXPORT KDHorizontalLine : public QFrame
{
    Q_OBJECT
    Q_PROPERTY(QString title READ title WRITE setTitle)
public:
    explicit KDHorizontalLine(QWidget *parent = nullptr, const char *name = nullptr,  Qt::WindowFlags f = {});
    explicit KDHorizontalLine(const QString &title, QWidget *parent = nullptr, const char *name = nullptr,  Qt::WindowFlags f = {});
    ~KDHorizontalLine() override;

    QString title() const
    {
        return mTitle;
    }

    /*! \reimp to hard-code the frame shape */
    void setFrameStyle(int style);

    QSize sizeHint() const override;
    QSize minimumSizeHint() const override;
    QSizePolicy sizePolicy() const;

    static int indentHint();

public Q_SLOTS:
    virtual void setTitle(const QString &title);

protected:
    void paintEvent(QPaintEvent *) override;

private:
    void calculateFrame();

private:
    QString mTitle;
    Qt::Alignment mAlign;
    int mLenVisible;
};

#endif /* __KDTOOLS__KDHORIZONTALLINE_H__ */

