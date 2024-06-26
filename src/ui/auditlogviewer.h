/*
  SPDX-FileCopyrightText: 2015-2021 Laurent Montel <montel@kde.org>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include "kleo_export.h"

#include <QDialog>

class QTextEdit;

namespace Kleo
{
class AuditLogEntry;

class KLEO_EXPORT AuditLogViewer : public QDialog
{
    Q_OBJECT
public:
    explicit AuditLogViewer(const QString &log, QWidget *parent = nullptr);

    ~AuditLogViewer() override;

    static void showAuditLog(QWidget *parent, const AuditLogEntry &auditLog, const QString &title = {});

    void setAuditLog(const QString &log);

private Q_SLOTS:
    void slotSaveAs();
    void slotCopyClip();

private:
    void writeConfig();
    void readConfig();

    QString m_log;
    QTextEdit *m_textEdit = nullptr;
};

}
