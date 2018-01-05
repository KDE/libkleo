/*
  Copyright (c) 2015-2018 Montel Laurent <montel@kde.org>

  This library is free software; you can redistribute it and/or modify it
  under the terms of the GNU Library General Public License as published by
  the Free Software Foundation; either version 2 of the License, or (at your
  option) any later version.

  This library is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
  License for more details.

  You should have received a copy of the GNU Library General Public License
  along with this library; see the file COPYING.LIB.  If not, write to the
  Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
  02110-1301, USA.

*/

#ifndef AUDITLOGVIEWER_H
#define AUDITLOGVIEWER_H

#include <QDialog>

#include <kleo_export.h>

#ifdef HAVE_PIMTEXTEDIT
#include "kpimtextedit/richtexteditorwidget.h"

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
#endif // AUDITLOGVIEWER_H
