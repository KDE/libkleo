/*
    test_kdhorizontalline.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-only
*/

#include "ui/kdhorizontalline.h"

#include <QApplication>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
int main(int argc, char *argv[])
{

    QApplication app(argc, argv);

    QWidget w;
    QGridLayout glay(&w);

    KDHorizontalLine hl1(QStringLiteral("Foo"), &w);
    glay.addWidget(&hl1, 0, 0, 1, 2);

    QLabel lb1(QStringLiteral("Foo 1:"), &w);
    glay.addWidget(&lb1, 1, 0);
    QLineEdit le1(&w);
    glay.addWidget(&le1, 1, 1);

    glay.setColumnStretch(1, 1);
    glay.setRowStretch(2, 1);

    w.show();

    return app.exec();
}
