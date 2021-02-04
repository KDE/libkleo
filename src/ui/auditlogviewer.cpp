/*
  SPDX-FileCopyrightText: 2015-2021 Laurent Montel <montel@kde.org>

  SPDX-License-Identifier: LGPL-2.0-or-later

*/
#include "auditlogviewer.h"

#ifdef HAVE_PIMTEXTEDIT
# include "kpimtextedit/richtexteditor.h"
#else
# include <QTextEdit>
#endif
#include <QSaveFile>
#include <QFileDialog>
#include <KConfigGroup>
#include <KMessageBox>
#include <KLocalizedString>
#include <KSharedConfig>
#include <QTextStream>
#include <QDialogButtonBox>
#include <QPushButton>
#include <QVBoxLayout>

using namespace Kleo::Private;

AuditLogViewer::AuditLogViewer(const QString &log, QWidget *parent)
    : QDialog(parent),
      m_log(/* sic */),
#ifdef HAVE_PIMTEXTEDIT
      m_textEdit(new KPIMTextEdit::RichTextEditorWidget(this))
#else
      m_textEdit(new QTextEdit(this))
#endif
{
    setWindowTitle(i18nc("@title:window", "View GnuPG Audit Log"));
    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Close);

    auto copyClipBtn = new QPushButton;
    copyClipBtn->setText(i18n("&Copy to Clipboard"));
    copyClipBtn->setIcon(QIcon::fromTheme(QStringLiteral("edit-copy")));
    buttonBox->addButton(copyClipBtn, QDialogButtonBox::ActionRole);
    connect(copyClipBtn, &QPushButton::clicked, this, &AuditLogViewer::slotCopyClip);

    auto saveAsBtn = new QPushButton;
    saveAsBtn->setText(i18n("&Save to Disk..."));
    saveAsBtn->setIcon(QIcon::fromTheme(QStringLiteral("document-save-as")));
    buttonBox->addButton(saveAsBtn, QDialogButtonBox::ActionRole);
    connect(saveAsBtn, &QPushButton::clicked, this, &AuditLogViewer::slotSaveAs);

    m_textEdit->setObjectName(QStringLiteral("m_textEdit"));
    m_textEdit->setReadOnly(true);

    auto mainLayout = new QVBoxLayout(this);
    mainLayout->addWidget(m_textEdit);
    mainLayout->addWidget(buttonBox);

    connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);

    setAuditLog(log);

    readConfig();
}

AuditLogViewer::~AuditLogViewer()
{
    writeConfig();
}

void AuditLogViewer::setAuditLog(const QString &log)
{
    if (log == m_log) {
        return;
    }
    m_log = log;
    m_textEdit->setHtml(QLatin1String("<qt>") + log + QLatin1String("</qt>"));
}

void AuditLogViewer::slotSaveAs()
{
    const QString fileName = QFileDialog::getSaveFileName(this, i18n("Choose File to Save GnuPG Audit Log to"));
    if (fileName.isEmpty()) {
        return;
    }

    QSaveFile file(fileName);

    if (file.open(QIODevice::WriteOnly)) {
        QTextStream s(&file);
        s << "<html><head>";
        if (!windowTitle().isEmpty()) {
            s << "\n<title>"
              << windowTitle().toHtmlEscaped()
              << "</title>\n";
        }
        s << "</head><body>\n"
          << m_log
          << "\n</body></html>\n";
        s.flush();
        file.commit();
    }

    if (const int err = file.error())
        KMessageBox::error(this, i18n("Could not save to file \"%1\": %2",
                                      file.fileName(), QString::fromLocal8Bit(strerror(err))),
                           i18n("File Save Error"));
}

void AuditLogViewer::slotCopyClip()
{
#ifdef HAVE_PIMTEXTEDIT
    m_textEdit->editor()->selectAll();
    m_textEdit->editor()->copy();
    m_textEdit->editor()->textCursor().clearSelection();
#else
    m_textEdit->selectAll();
    m_textEdit->copy();
    m_textEdit->textCursor().clearSelection();
#endif
}

void AuditLogViewer::readConfig()
{
    KConfigGroup group(KSharedConfig::openConfig(), "AuditLogViewer");
    const QSize size = group.readEntry("Size", QSize());
    if (size.isValid()) {
        resize(size);
    } else {
        resize(600, 400);
    }
}

void AuditLogViewer::writeConfig()
{
    KConfigGroup group(KSharedConfig::openConfig(), "AuditLogViewer");
    group.writeEntry("Size", size());
    group.sync();
}

