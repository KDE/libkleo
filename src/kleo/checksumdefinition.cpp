/* -*- mode: c++; c-basic-offset:4 -*-
    checksumdefinition.cpp

    This file is part of libkleopatra, the KDE keymanagement library
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "checksumdefinition.h"

#include "kleoexception.h"

#include "libkleo_debug.h"

#include <KConfigGroup>
#include <KLocalizedString>
#include <KConfig>
#include <KShell>

#include <QDebug>
#include <QFileInfo>
#include <QProcess>
#include <QByteArray>
#include <QMutex>
#include <QCoreApplication>
#include <QRegularExpression>

#include <KSharedConfig>
#include <QStandardPaths>

#ifdef stdin
# undef stdin // pah..
#endif

using namespace Kleo;

static QMutex installPathMutex;
Q_GLOBAL_STATIC(QString, _installPath)
QString ChecksumDefinition::installPath()
{
    const QMutexLocker locker(&installPathMutex);
    QString *const ip = _installPath();
    if (ip->isEmpty()) {
        if (QCoreApplication::instance()) {
            *ip = QCoreApplication::applicationDirPath();
        } else {
            qCWarning(LIBKLEO_LOG) << "checksumdefinition.cpp: installPath() called before QCoreApplication was constructed";
        }
    }
    return *ip;
}
void ChecksumDefinition::setInstallPath(const QString &ip)
{
    const QMutexLocker locker(&installPathMutex);
    *_installPath() = ip;
}

// Checksum Definition #N groups
static const QLatin1String ID_ENTRY("id");
static const QLatin1String NAME_ENTRY("Name");
static const QLatin1String CREATE_COMMAND_ENTRY("create-command");
static const QLatin1String VERIFY_COMMAND_ENTRY("verify-command");
static const QLatin1String FILE_PATTERNS_ENTRY("file-patterns");
static const QLatin1String OUTPUT_FILE_ENTRY("output-file");
static const QLatin1String FILE_PLACEHOLDER("%f");
static const QLatin1String INSTALLPATH_PLACEHOLDER("%I");
static const QLatin1String NULL_SEPARATED_STDIN_INDICATOR("0|");
static const QLatin1Char   NEWLINE_SEPARATED_STDIN_INDICATOR('|');

// ChecksumOperations group
static const QLatin1String CHECKSUM_DEFINITION_ID_ENTRY("checksum-definition-id");

namespace
{

class ChecksumDefinitionError : public Kleo::Exception
{
    const QString m_id;
public:
    ChecksumDefinitionError(const QString &id, const QString &message)
        : Kleo::Exception(GPG_ERR_INV_PARAMETER, i18n("Error in checksum definition %1: %2", id, message), MessageOnly),
          m_id(id)
    {

    }
    ~ChecksumDefinitionError() throw() {}

    const QString &checksumDefinitionId() const
    {
        return m_id;
    }
};

}

static QString try_extensions(const QString &path)
{
    static const char exts[][4] = {
        "", "exe", "bat", "bin", "cmd",
    };
    static const size_t numExts = sizeof exts / sizeof * exts;
    for (unsigned int i = 0; i < numExts; ++i) {
        const QFileInfo fi(path + QLatin1Char('.') + QLatin1String(exts[i]));
        if (fi.exists()) {
            return fi.filePath();
        }
    }
    return QString();
}

static void parse_command(QString cmdline, const QString &id, const QString &whichCommand,
                          QString *command, QStringList *prefix, QStringList *suffix, ChecksumDefinition::ArgumentPassingMethod *method)
{
    Q_ASSERT(prefix);
    Q_ASSERT(suffix);
    Q_ASSERT(method);

    KShell::Errors errors;
    QStringList l;

    if (cmdline.startsWith(NULL_SEPARATED_STDIN_INDICATOR)) {
        *method = ChecksumDefinition::NullSeparatedInputFile;
        cmdline.remove(0, 2);
    } else if (cmdline.startsWith(NEWLINE_SEPARATED_STDIN_INDICATOR)) {
        *method = ChecksumDefinition::NewlineSeparatedInputFile;
        cmdline.remove(0, 1);
    } else {
        *method = ChecksumDefinition::CommandLine;
    }
    if (*method != ChecksumDefinition::CommandLine && cmdline.contains(FILE_PLACEHOLDER)) {
        throw ChecksumDefinitionError(id, i18n("Cannot use both %f and | in '%1'", whichCommand));
    }
    cmdline.replace(FILE_PLACEHOLDER,        QLatin1String("__files_go_here__"))
    .replace(INSTALLPATH_PLACEHOLDER, QStringLiteral("__path_goes_here__"));
    l = KShell::splitArgs(cmdline, KShell::AbortOnMeta | KShell::TildeExpand, &errors);
    l = l.replaceInStrings(QStringLiteral("__files_go_here__"), FILE_PLACEHOLDER);
    if (l.indexOf(QRegExp(QLatin1String(".*__path_goes_here__.*"))) >= 0) {
        l = l.replaceInStrings(QStringLiteral("__path_goes_here__"), ChecksumDefinition::installPath());
    }
    if (errors == KShell::BadQuoting) {
        throw ChecksumDefinitionError(id, i18n("Quoting error in '%1' entry", whichCommand));
    }
    if (errors == KShell::FoundMeta) {
        throw ChecksumDefinitionError(id, i18n("'%1' too complex (would need shell)", whichCommand));
    }
    qCDebug(LIBKLEO_LOG) << "ChecksumDefinition[" << id << ']' << l;
    if (l.empty()) {
        throw ChecksumDefinitionError(id, i18n("'%1' entry is empty/missing", whichCommand));
    }
    const QFileInfo fi1(l.front());
    if (fi1.isAbsolute()) {
        *command = try_extensions(l.front());
    } else {
        *command = QStandardPaths::findExecutable(fi1.fileName());
    }
    if (command->isEmpty()) {
        throw ChecksumDefinitionError(id, i18n("'%1' empty or not found", whichCommand));
    }
    const int idx1 = l.indexOf(FILE_PLACEHOLDER);
    if (idx1 < 0) {
        // none -> append
        *prefix = l.mid(1);
    } else {
        *prefix = l.mid(1, idx1 - 1);
        *suffix = l.mid(idx1 + 1);
    }
    switch (*method) {
    case ChecksumDefinition::CommandLine:
        qCDebug(LIBKLEO_LOG) << "ChecksumDefinition[" << id << ']' << *command << *prefix << FILE_PLACEHOLDER << *suffix;
        break;
    case ChecksumDefinition::NewlineSeparatedInputFile:
        qCDebug(LIBKLEO_LOG) << "ChecksumDefinition[" << id << ']' << "find | " << *command << *prefix;
        break;
    case ChecksumDefinition::NullSeparatedInputFile:
        qCDebug(LIBKLEO_LOG) << "ChecksumDefinition[" << id << ']' << "find -print0 | " << *command << *prefix;
        break;
    case ChecksumDefinition::NumArgumentPassingMethods:
        Q_ASSERT(!"Should not happen");
        break;
    }
}

namespace
{

class KConfigBasedChecksumDefinition : public ChecksumDefinition
{
public:
    explicit KConfigBasedChecksumDefinition(const KConfigGroup &group)
        : ChecksumDefinition(group.readEntryUntranslated(ID_ENTRY),
                             group.readEntry(NAME_ENTRY),
                             group.readEntry(OUTPUT_FILE_ENTRY),
                             group.readEntry(FILE_PATTERNS_ENTRY, QStringList()))
    {
        if (id().isEmpty()) {
            throw ChecksumDefinitionError(group.name(), i18n("'id' entry is empty/missing"));
        }
        if (outputFileName().isEmpty()) {
            throw ChecksumDefinitionError(id(), i18n("'output-file' entry is empty/missing"));
        }
        if (patterns().empty()) {
            throw ChecksumDefinitionError(id(), i18n("'file-patterns' entry is empty/missing"));
        }

        // create-command
        ArgumentPassingMethod method;
        parse_command(group.readEntry(CREATE_COMMAND_ENTRY), id(), CREATE_COMMAND_ENTRY,
                      &m_createCommand, &m_createPrefixArguments, &m_createPostfixArguments, &method);
        setCreateCommandArgumentPassingMethod(method);

        // verify-command
        parse_command(group.readEntry(VERIFY_COMMAND_ENTRY), id(), VERIFY_COMMAND_ENTRY,
                      &m_verifyCommand, &m_verifyPrefixArguments, &m_verifyPostfixArguments, &method);
        setVerifyCommandArgumentPassingMethod(method);
    }

private:
    QString doGetCreateCommand() const override
    {
        return m_createCommand;
    }
    QStringList doGetCreateArguments(const QStringList &files) const override
    {
        return m_createPrefixArguments + files + m_createPostfixArguments;
    }
    QString doGetVerifyCommand() const override
    {
        return m_verifyCommand;
    }
    QStringList doGetVerifyArguments(const QStringList &files) const override
    {
        return m_verifyPrefixArguments + files + m_verifyPostfixArguments;
    }

private:
    QString m_createCommand, m_verifyCommand;
    QStringList m_createPrefixArguments, m_createPostfixArguments;
    QStringList m_verifyPrefixArguments, m_verifyPostfixArguments;
};

}

ChecksumDefinition::ChecksumDefinition(const QString &id, const QString &label, const QString &outputFileName, const QStringList &patterns)
    : m_id(id),
      m_label(label.isEmpty() ? id : label),
      m_outputFileName(outputFileName),
      m_patterns(patterns),
      m_createMethod(CommandLine),
      m_verifyMethod(CommandLine)
{

}

ChecksumDefinition::~ChecksumDefinition() {}

QString ChecksumDefinition::createCommand() const
{
    return doGetCreateCommand();
}

QString ChecksumDefinition::verifyCommand() const
{
    return doGetVerifyCommand();
}

#if 0
QStringList ChecksumDefinition::createCommandArguments(const QStringList &files) const
{
    return doGetCreateArguments(files);
}

QStringList ChecksumDefinition::verifyCommandArguments(const QStringList &files) const
{
    return doGetVerifyArguments(files);
}
#endif

static QByteArray make_input(const QStringList &files, char sep)
{
    QByteArray result;
    for (const QString &file : files) {
        result += QFile::encodeName(file);
        result += sep;
    }
    return result;
}

static bool start_command(QProcess *p, const char *functionName,
                          const QString &cmd, const QStringList &args,
                          const QStringList &files, ChecksumDefinition::ArgumentPassingMethod method)
{
    if (!p) {
        qCWarning(LIBKLEO_LOG) << functionName << ": process == NULL";
        return false;
    }

    switch (method) {

    case ChecksumDefinition::NumArgumentPassingMethods:
        Q_ASSERT(!"Should not happen");

    case ChecksumDefinition::CommandLine:
        qCDebug(LIBKLEO_LOG) << "Starting: " << cmd << " " << args.join(QLatin1Char(' '));
        p->start(cmd, args, QIODevice::ReadOnly);
        return true;

    case ChecksumDefinition::NewlineSeparatedInputFile:
    case ChecksumDefinition::NullSeparatedInputFile:
        qCDebug(LIBKLEO_LOG) << "Starting: " << cmd << " " << args.join(QLatin1Char(' '));
        p->start(cmd, args, QIODevice::ReadWrite);
        if (!p->waitForStarted()) {
            return false;
        }
        const char sep =
            method == ChecksumDefinition::NewlineSeparatedInputFile ? '\n' :
            /* else */                            '\0';
        const QByteArray stdin = make_input(files, sep);
        if (p->write(stdin) != stdin.size()) {
            return false;
        }
        p->closeWriteChannel();
        return true;
    }

    return false; // make compiler happy

}

bool ChecksumDefinition::startCreateCommand(QProcess *p, const QStringList &files) const
{
    return start_command(p, Q_FUNC_INFO,
                         doGetCreateCommand(),
                         m_createMethod == CommandLine ? doGetCreateArguments(files) :
                         /* else */                      doGetCreateArguments(QStringList()),
                         files, m_createMethod);
}

bool ChecksumDefinition::startVerifyCommand(QProcess *p, const QStringList &files) const
{
    return start_command(p, Q_FUNC_INFO,
                         doGetVerifyCommand(),
                         m_verifyMethod == CommandLine ? doGetVerifyArguments(files) :
                         /* else */                      doGetVerifyArguments(QStringList()),
                         files, m_verifyMethod);
}

// static
std::vector< std::shared_ptr<ChecksumDefinition> > ChecksumDefinition::getChecksumDefinitions()
{
    QStringList errors;
    return getChecksumDefinitions(errors);
}

// static
std::vector< std::shared_ptr<ChecksumDefinition> > ChecksumDefinition::getChecksumDefinitions(QStringList &errors)
{
    std::vector< std::shared_ptr<ChecksumDefinition> > result;
    KSharedConfigPtr config = KSharedConfig::openConfig(QStringLiteral("libkleopatrarc"));
    const QStringList groups = config->groupList().filter(QRegularExpression(QStringLiteral("^Checksum Definition #")));
    result.reserve(groups.size());
    for (const QString &group : groups)
        try {
            const std::shared_ptr<ChecksumDefinition> ad(new KConfigBasedChecksumDefinition(KConfigGroup(config, group)));
            result.push_back(ad);
        } catch (const std::exception &e) {
            qDebug() << e.what();
            errors.push_back(QString::fromLocal8Bit(e.what()));
        } catch (...) {
            errors.push_back(i18n("Caught unknown exception in group %1", group));
        }
    return result;
}

// static
std::shared_ptr<ChecksumDefinition> ChecksumDefinition::getDefaultChecksumDefinition(const std::vector< std::shared_ptr<ChecksumDefinition> > &checksumDefinitions)
{
    const KConfigGroup group(KSharedConfig::openConfig(), "ChecksumOperations");
    const QString checksumDefinitionId = group.readEntry(CHECKSUM_DEFINITION_ID_ENTRY, QStringLiteral("sha256sum"));

    if (!checksumDefinitionId.isEmpty())
        for (const std::shared_ptr<ChecksumDefinition> &cd : checksumDefinitions)
            if (cd && cd->id() == checksumDefinitionId) {
                return cd;
            }
    if (!checksumDefinitions.empty()) {
        return checksumDefinitions.front();
    } else {
        return std::shared_ptr<ChecksumDefinition>();
    }
}

// static
void ChecksumDefinition::setDefaultChecksumDefinition(const std::shared_ptr<ChecksumDefinition> &checksumDefinition)
{
    if (!checksumDefinition) {
        return;
    }
    KConfigGroup group(KSharedConfig::openConfig(), "ChecksumOperations");
    group.writeEntry(CHECKSUM_DEFINITION_ID_ENTRY, checksumDefinition->id());
    group.sync();
}
