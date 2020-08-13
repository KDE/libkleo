/*
    test_keygen.h

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-only
*/

#ifndef __KLEO_TEST_KEYGEN_H__
#define __KLEO_TEST_KEYGEN_H__

#include <QDialog>

#include <QByteArray>

namespace GpgME
{
class Error;
class KeyGenerationResult;
}

class QLineEdit;

class KeyGenerator : public QDialog
{
    Q_OBJECT
public:
    KeyGenerator(QWidget *parent = nullptr);
    ~KeyGenerator();

public Q_SLOTS:
    void slotStartKeyGeneration();
    void slotResult(const GpgME::KeyGenerationResult &res, const QByteArray &keyData);
private:
    void showError(const GpgME::Error &err);

private:
    QLineEdit *mLineEdits[20];
};

#endif // __KLEO_TEST_KEYGEN_H__
