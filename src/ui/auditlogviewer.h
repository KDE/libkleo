/*
  SPDX-FileCopyrightText: 2015-2021 Laurent Montel <montel@kde.org>

  SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include <QDialog>

#include <kleo_export.h>

#ifdef HAVE_PIMTEXTEDIT
#include <KPIMTextEdit/RichTextEditorWidget>

namespace KPIMTextEdit
{
class RichTextEditorWidget;
}
#else

class QTextEdit;
#endif // HAVE_PIMTEXTEDIT

namespace Kleo
{
namespace Private
{

class KLEO_EXPORT AuditLogViewer : public QDialog
{
    Q_OBJECT
public:
    explicit AuditLogViewer(const QString &log, QWidget *parent = nullptr);

    ~AuditLogViewer();

    void setAuditLog(const QString &log);

private Q_SLOTS:
    void slotSaveAs();
    void slotCopyClip();

private:
    void writeConfig();
    void readConfig();

    QString m_log;
#ifdef HAVE_PIMTEXTEDIT
    KPIMTextEdit::RichTextEditorWidget *m_textEdit = nullptr;
#else
    QTextEdit *m_textEdit = nullptr;
#endif
};

}
}
