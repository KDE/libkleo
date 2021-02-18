/* -*- Mode: C++ -*-
   KD Tools - a set of useful widgets for Qt
*/

/****************************************************************************
** SPDX-FileCopyrightText: 2005 Klarälvdalens Datakonsult AB.  All rights reserved.
**
** This file is part of the KD Tools library.
**
** SPDX-License-Identifier: GPL-2.0-or-later
**
**********************************************************************/

#include "kdhorizontalline.h"

#include <QStyle>
#include <QPainter>
#ifdef QT_ACCESSIBILITY_SUPPORT
#include <QAccessible>
#endif
#include <QFontMetrics>
#include <QApplication>
#include <QPaintEvent>

KDHorizontalLine::KDHorizontalLine(QWidget *parent, const char *name, Qt::WindowFlags f)
    : QFrame(parent, f),
      mAlign(Qt::AlignLeft),
      mLenVisible(0)
{
    setObjectName(QLatin1String(name));
    QFrame::setFrameStyle(HLine | Sunken);
}

KDHorizontalLine::KDHorizontalLine(const QString &title, QWidget *parent, const char *name, Qt::WindowFlags f)
    : QFrame(parent, f),
      mAlign(Qt::AlignLeft),
      mLenVisible(0)
{
    setObjectName(QLatin1String(name));
    QFrame::setFrameStyle(HLine | Sunken);
    setTitle(title);
}

KDHorizontalLine::~KDHorizontalLine() {}

void KDHorizontalLine::setFrameStyle(int style)
{
    QFrame::setFrameStyle((style & ~Shape_Mask) | HLine);     // force HLine
}

void KDHorizontalLine::setTitle(const QString &title)
{
    if (mTitle == title) {
        return;
    }
    mTitle = title;
    calculateFrame();
    update();
    updateGeometry();
#ifdef QT_ACCESSIBILITY_SUPPORT
    QAccessible::updateAccessibility(this, 0, QAccessible::NameChanged);
#endif
}

void KDHorizontalLine::calculateFrame()
{
    mLenVisible = mTitle.length();
#if 0
    if (mLenVisible) {
        const QFontMetrics fm = fontMetrics();
        while (mLenVisible) {
            const int tw = fm.width(mTitle, mLenVisible) + 4 * fm.width(QChar(' '));
            if (tw < width()) {
                break;
            }
            mLenVisible--;
        }
        qDebug("mLenVisible = %d (of %d)", mLenVisible, mTitle.length());
        if (mLenVisible) {   // but do we also have a visible label?
            QRect r = rect();
            const int va = style().styleHint(QStyle::SH_GroupBox_TextLabelVerticalAlignment, this);
            if (va & Qt::AlignVCenter) {
                r.setTop(fm.height() / 2);    // frame rect should be
            } else if (va & Qt::AlignTop) {
                r.setTop(fm.ascent());
            }
            setFrameRect(r);                          //   smaller than client rect
            return;
        }
    }
    // no visible label
    setFrameRect(QRect(0, 0, 0, 0));               //  then use client rect
#endif
}

QSizePolicy KDHorizontalLine::sizePolicy() const
{
    return {QSizePolicy::Minimum, QSizePolicy::Fixed};
}

QSize KDHorizontalLine::sizeHint() const
{
    return minimumSizeHint();
}

QSize KDHorizontalLine::minimumSizeHint() const
{
    const int w = fontMetrics().horizontalAdvance(mTitle, mLenVisible) +
                  fontMetrics().boundingRect(QLatin1Char(' ')).width();
    const int h = fontMetrics().height();
    return QSize(qMax(w, indentHint()), h).expandedTo(qApp->globalStrut());
}

void KDHorizontalLine::paintEvent(QPaintEvent *e)
{
    QPainter paint(this);

    if (mLenVisible) {          // draw title
        const QFontMetrics &fm = paint.fontMetrics();
        const int h = fm.height();
        const int tw = fm.horizontalAdvance(mTitle, mLenVisible) + fm.horizontalAdvance(QLatin1Char(' '));
        int x;
        if (mAlign & Qt::AlignHCenter) {                // center alignment
            x = frameRect().width() / 2 - tw / 2;
        } else if (mAlign & Qt::AlignRight) {      // right alignment
            x = frameRect().width() - tw;
        } else if (mAlign & Qt::AlignLeft) {     // left alignment
            x = 0;
        } else { // auto align
            if (QApplication::isRightToLeft()) {
                x = frameRect().width() - tw;
            } else {
                x = 0;
            }
        }
        QRect r(x, 0, tw, h);
        int va = style()->styleHint(QStyle::SH_GroupBox_TextLabelVerticalAlignment, nullptr, this);
        if (va & Qt::AlignTop) {
            r.translate(0, fm.descent());
        }
        const QColor pen((QRgb) style()->styleHint(QStyle::SH_GroupBox_TextLabelColor, nullptr, this));
        if (!style()->styleHint(QStyle::SH_UnderlineShortcut, nullptr, this)) {
            va |= Qt::TextHideMnemonic;
        }
        style()->drawItemText(&paint, r, Qt::TextShowMnemonic | Qt::AlignHCenter | va, palette(),
                              isEnabled(), mTitle);
        paint.setClipRegion(e->region().subtracted(r));     // clip everything but title
    }
    drawFrame(&paint);
}

// static
int KDHorizontalLine::indentHint()
{
    return 30;
}

