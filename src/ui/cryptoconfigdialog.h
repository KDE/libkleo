/*
    cryptoconfigdialog.h

    This file is part of kgpgcertmanager
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifndef CRYPTOCONFIGDIALOG_H
#define CRYPTOCONFIGDIALOG_H

#include "kleo_export.h"
#include <QDialog>
class QDialogButtonBox;

namespace QGpgME
{
class CryptoConfig;
} // namespace QGpgME

namespace Kleo
{

class CryptoConfigModule;

/**
 * Simple QDialog wrapper around CryptoConfigModule
 */
class KLEO_EXPORT CryptoConfigDialog : public QDialog
{
    Q_OBJECT
public:
    explicit CryptoConfigDialog(QGpgME::CryptoConfig *config, QWidget *parent = nullptr);

protected Q_SLOTS:
    void slotOk();
    void slotCancel();
    void slotDefault();
    void slotApply();
    void slotUser1(); // reset

public Q_SLOTS:
    void slotChanged();

private:
    CryptoConfigModule *mMainWidget = nullptr;
    QDialogButtonBox *mButtonBox = nullptr;
};

}

#endif /* CRYPTOCONFIGDIALOG_H */

