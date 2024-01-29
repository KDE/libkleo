/*
    SPDX-FileCopyrightText: 2015-2021 Laurent Montel <montel@kde.org>
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include <config-libkleo.h>

#include "auditlogviewer.h"

#include <libkleo/auditlogentry.h>
#include <libkleo/formatting.h>

#include <KConfigGroup>
#include <KGuiItem>
#include <KLocalizedString>
#include <KMessageBox>
#include <KSharedConfig>
#include <KStandardGuiItem>

#ifdef HAVE_PIMTEXTEDIT
#include <TextCustomEditor/RichTextEditor>
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

#include <gpgme++/error.h>

using namespace Kleo;

AuditLogViewer::AuditLogViewer(const QString &log, QWidget *parent)
    : QDialog(parent)
    , m_log(/* sic */)
    ,
#ifdef HAVE_PIMTEXTEDIT
    m_textEdit(new TextCustomEditor::RichTextEditorWidget(this))
#else
    m_textEdit(new QTextEdit(this))
#endif
{
    setWindowTitle(i18nc("@title:window", "View GnuPG Audit Log"));
    QDialogButtonBox *buttonBox = new QDialogButtonBox{};

    auto copyClipBtn = buttonBox->addButton(i18n("&Copy to Clipboard"), QDialogButtonBox::ActionRole);
    copyClipBtn->setObjectName(QLatin1StringView("copyClipBtn"));
    copyClipBtn->setIcon(QIcon::fromTheme(QStringLiteral("edit-copy")));
    connect(copyClipBtn, &QPushButton::clicked, this, &AuditLogViewer::slotCopyClip);

    auto saveAsBtn = buttonBox->addButton(i18n("&Save to Disk..."), QDialogButtonBox::ActionRole);
    saveAsBtn->setObjectName(QLatin1StringView("saveAsBtn"));
    saveAsBtn->setIcon(QIcon::fromTheme(QStringLiteral("document-save-as")));
    connect(saveAsBtn, &QPushButton::clicked, this, &AuditLogViewer::slotSaveAs);

    auto closeBtn = buttonBox->addButton(QString{}, QDialogButtonBox::AcceptRole);
    closeBtn->setObjectName(QLatin1StringView("Close"));
    KGuiItem::assign(closeBtn, KStandardGuiItem::close());

    m_textEdit->setObjectName(QLatin1StringView("m_textEdit"));
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

// static
void AuditLogViewer::showAuditLog(QWidget *parent, const AuditLogEntry &auditLog, const QString &title)
{
    const GpgME::Error err = auditLog.error();
    if (err.code() == GPG_ERR_NOT_IMPLEMENTED) {
        KMessageBox::information(parent, i18n("Your system does not have support for GnuPG Audit Logs"), i18n("System Error"));
        return;
    }
    if (err && err.code() != GPG_ERR_NO_DATA) {
        KMessageBox::information(parent,
                                 i18n("An error occurred while trying to retrieve the GnuPG Audit Log:\n%1", Formatting::errorAsString(err)),
                                 i18n("GnuPG Audit Log Error"));
        return;
    }
    if (auditLog.text().isEmpty()) {
        KMessageBox::information(parent, i18n("No GnuPG Audit Log available for this operation."), i18n("No GnuPG Audit Log"));
        return;
    }

    const auto alv = new AuditLogViewer{auditLog.text(), parent};
    alv->setAttribute(Qt::WA_DeleteOnClose);
    alv->setWindowTitle(title.isEmpty() ? i18n("GnuPG Audit Log Viewer") : title);
    alv->show();
}

void AuditLogViewer::setAuditLog(const QString &log)
{
    if (log == m_log) {
        return;
    }
    m_log = log;
    m_textEdit->setHtml(QLatin1StringView("<qt>") + log + QLatin1String("</qt>"));
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
    KConfigGroup group(KSharedConfig::openConfig(), QStringLiteral("AuditLogViewer"));
    const QSize size = group.readEntry("Size", QSize());
    if (size.isValid()) {
        resize(size);
    } else {
        resize(600, 400);
    }
}

void AuditLogViewer::writeConfig()
{
    KConfigGroup group(KSharedConfig::openConfig(), QStringLiteral("AuditLogViewer"));
    group.writeEntry("Size", size());
    group.sync();
}

#include "moc_auditlogviewer.cpp"
