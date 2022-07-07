/*
    SPDX-FileCopyrightText: 2015-2021 Laurent Montel <montel@kde.org>
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "auditlogviewer.h"

#include <KConfigGroup>
#include <KGuiItem>
#include <KLocalizedString>
#include <KMessageBox>
#include <KSharedConfig>
#include <KStandardGuiItem>

#ifdef HAVE_PIMTEXTEDIT
#include <KPIMTextEdit/RichTextEditor>
#else
#include <QTextEdit>
#endif

#include <QDebug>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QPushButton>
#include <QSaveFile>
#include <QStyle>
#include <QTextStream>
#include <QVBoxLayout>

using namespace Kleo::Private;

AuditLogViewer::AuditLogViewer(const QString &log, QWidget *parent)
    : QDialog(parent)
    , m_log(/* sic */)
    ,
#ifdef HAVE_PIMTEXTEDIT
    m_textEdit(new KPIMTextEdit::RichTextEditorWidget(this))
#else
    m_textEdit(new QTextEdit(this))
#endif
{
    setWindowTitle(i18nc("@title:window", "View GnuPG Audit Log"));
    QDialogButtonBox *buttonBox = new QDialogButtonBox{};

    auto copyClipBtn = buttonBox->addButton(i18n("&Copy to Clipboard"), QDialogButtonBox::ActionRole);
    copyClipBtn->setObjectName(QStringLiteral("copyClipBtn"));
    copyClipBtn->setIcon(QIcon::fromTheme(QStringLiteral("edit-copy")));
    connect(copyClipBtn, &QPushButton::clicked, this, &AuditLogViewer::slotCopyClip);

    auto saveAsBtn = buttonBox->addButton(i18n("&Save to Disk..."), QDialogButtonBox::ActionRole);
    saveAsBtn->setObjectName(QStringLiteral("saveAsBtn"));
    saveAsBtn->setIcon(QIcon::fromTheme(QStringLiteral("document-save-as")));
    connect(saveAsBtn, &QPushButton::clicked, this, &AuditLogViewer::slotSaveAs);

    auto closeBtn = buttonBox->addButton(QString{}, QDialogButtonBox::AcceptRole);
    closeBtn->setObjectName(QStringLiteral("Close"));
    KGuiItem::assign(closeBtn, KStandardGuiItem::close());

    m_textEdit->setObjectName(QStringLiteral("m_textEdit"));
    m_textEdit->setReadOnly(true);

    auto mainLayout = new QVBoxLayout(this);
    mainLayout->addWidget(m_textEdit);
    mainLayout->addWidget(buttonBox);

#if 0
    qDebug() << "buttonBox->style()->styleHint(QStyle::SH_DialogButtonLayout, ...):" << buttonBox->style()->styleHint(QStyle::SH_DialogButtonLayout, nullptr, buttonBox);
    qDebug() << __func__ << "buttonBox->focusProxy():" << buttonBox->focusProxy();
    qDebug() << __func__ << "copyClipBtn->nextInFocusChain():" << copyClipBtn->nextInFocusChain();
    qDebug() << __func__ << "saveAsBtn->nextInFocusChain():" << saveAsBtn->nextInFocusChain();
    qDebug() << __func__ << "closeBtn->nextInFocusChain():" << closeBtn->nextInFocusChain();
#endif

    connect(buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
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
            s << "\n<title>" << windowTitle().toHtmlEscaped() << "</title>\n";
        }
        s << "</head><body>\n" << m_log << "\n</body></html>\n";
        s.flush();
        file.commit();
    }

    if (const int err = file.error()) {
        KMessageBox::error(this, i18n("Could not save to file \"%1\": %2", file.fileName(), QString::fromLocal8Bit(strerror(err))), i18n("File Save Error"));
    }
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
