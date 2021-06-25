/*
    test_cryptoconfig.cpp

    This file is part of libkleopatra's test suite.
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-only
*/

#include "utils/compat.h"

#include <qgpgme/qgpgmenewcryptoconfig.h>

#include <QCoreApplication>
#include <iostream>

using namespace std;
using namespace QGpgME;

#include <gpgme++/global.h>
#include <gpgme++/error.h>
#include <gpgme++/engineinfo.h>

#include <stdlib.h>

#include <gpgme++/gpgmepp_version.h>

int main(int argc, char **argv)
{

    if (GpgME::initializeLibrary(0)) {
        return 1;
    }

    if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.2.2") {
        cerr << "This test requires GnuPG 2.2.2 or later.";
        return 1;
    }

    QCoreApplication::setApplicationName(QStringLiteral("test_cryptoconfig"));
    QCoreApplication app(argc, argv);

    QGpgME::CryptoConfig *config = new QGpgMENewCryptoConfig;

    // Dynamic querying of the options
    cout << "Components:" << endl;
    QStringList components = config->componentList();

    for (QStringList::Iterator compit = components.begin(); compit != components.end(); ++compit) {
        cout << "Component " << (*compit).toLocal8Bit().constData() << ":" << endl;
        const QGpgME::CryptoConfigComponent *comp = config->component(*compit);
        Q_ASSERT(comp);
        QStringList groups = comp->groupList();
        for (QStringList::Iterator groupit = groups.begin(); groupit != groups.end(); ++groupit) {
            const QGpgME::CryptoConfigGroup *group = comp->group(*groupit);
            Q_ASSERT(group);
            cout << " Group " << (*groupit).toLocal8Bit().constData() << ": descr=\"" << group->description().toLocal8Bit().constData() << "\""
                 << " level=" << group->level() << endl;
            QStringList entries = group->entryList();
            for (QStringList::Iterator entryit = entries.begin(); entryit != entries.end(); ++entryit) {
                const QGpgME::CryptoConfigEntry *entry = group->entry(*entryit);
                Q_ASSERT(entry);
                cout << "  Entry " << (*entryit).toLocal8Bit().constData() << ":"
                     << " descr=\"" << entry->description().toLocal8Bit().constData() << "\""
                     << " " << (entry->isSet() ? "is set" : "is not set");
                if (!entry->isList())
                    switch (entry->argType()) {
                    case QGpgME::CryptoConfigEntry::ArgType_None:
                        break;
                    case QGpgME::CryptoConfigEntry::ArgType_Int:
                        cout << " int value=" << entry->intValue();
                        break;
                    case QGpgME::CryptoConfigEntry::ArgType_UInt:
                        cout << " uint value=" << entry->uintValue();
                        break;
                    case QGpgME::CryptoConfigEntry::ArgType_LDAPURL:
                    case QGpgME::CryptoConfigEntry::ArgType_Path:
                    // fallthrough
                    case QGpgME::CryptoConfigEntry::ArgType_DirPath:
                    // fallthrough
                    case QGpgME::CryptoConfigEntry::ArgType_String:

                        cout << " string value=" << entry->stringValue().toLocal8Bit().constData();
                        break;
                    case QGpgME::CryptoConfigEntry::NumArgType:
                        // just metadata and should never actually occur in the switch
                        break;
                    }
                else { // lists
                    switch (entry->argType()) {
                    case QGpgME::CryptoConfigEntry::ArgType_None: {
                        cout << " set " << entry->numberOfTimesSet() << " times";
                        break;
                    }
                    case QGpgME::CryptoConfigEntry::ArgType_Int: {
                        // (marc) if an entry isn't optional, you have to unset it for the default to take effect, so this Q_ASSERT is wrong:
                        // Q_ASSERT( entry->isOptional() ); // empty lists must be allowed (see https://www.intevation.de/roundup/aegypten/issue121)
                        std::vector<int> lst = entry->intValueList();
                        QString str;
                        for (std::vector<int>::const_iterator it = lst.begin(); it != lst.end(); ++it) {
                            str += QString::number(*it);
                        }
                        cout << " int values=" << str.toLocal8Bit().constData();
                        break;
                    }
                    case QGpgME::CryptoConfigEntry::ArgType_UInt: {
                        // (marc) if an entry isn't optional, you have to unset it for the default to take effect, so this Q_ASSERT is wrong:
                        // Q_ASSERT( entry->isOptional() ); // empty lists must be allowed (see https://www.intevation.de/roundup/aegypten/issue121)
                        std::vector<uint> lst = entry->uintValueList();
                        QString str;
                        for (std::vector<uint>::const_iterator it = lst.begin(); it != lst.end(); ++it) {
                            str += QString::number(*it);
                        }
                        cout << " uint values=" << str.toLocal8Bit().constData();
                        break;
                    }
                    case QGpgME::CryptoConfigEntry::ArgType_LDAPURL: {
                        // (marc) if an entry isn't optional, you have to unset it for the default to take effect, so this Q_ASSERT is wrong:
                        // Q_ASSERT( entry->isOptional() ); // empty lists must be allowed (see https://www.intevation.de/roundup/aegypten/issue121)
                        const QList<QUrl> urls = entry->urlValueList();
                        cout << " url values ";
                        for (const QUrl &url : urls) {
                            cout << url.toString().toLocal8Bit().constData() << " ";
                        }
                        cout << endl;
                    }
                    // fallthrough
                    case QGpgME::CryptoConfigEntry::ArgType_Path:
                    // fallthrough
                    case QGpgME::CryptoConfigEntry::ArgType_DirPath:
                    // fallthrough
                    case QGpgME::CryptoConfigEntry::ArgType_String:
                    // fallthrough string value lists were removed from
                    // gpgconf in 2008
                    case QGpgME::CryptoConfigEntry::NumArgType:
                        // just metadata and should never actually occur in the switch
                        break;
                    }
                }
                cout << endl;
            }
            // ...
        }
    }

    {
        // Static querying of a single boolean option
        static const char *s_entryName = "quiet";
        QGpgME::CryptoConfigEntry *entry = Kleo::getCryptoConfigEntry(config, "dirmngr", s_entryName);
        if (entry) {
            Q_ASSERT(entry->argType() == QGpgME::CryptoConfigEntry::ArgType_None);
            bool val = entry->boolValue();
            cout << "quiet option initially: " << (val ? "is set" : "is not set") << endl;

            entry->setBoolValue(!val);
            Q_ASSERT(entry->isDirty());
            config->sync(true);

            // Clear cached values!
            config->clear();

            // Check new value
            entry = Kleo::getCryptoConfigEntry(config, "dirmngr", s_entryName);
            Q_ASSERT(entry);
            Q_ASSERT(entry->argType() == QGpgME::CryptoConfigEntry::ArgType_None);
            cout << "quiet option now: " << (val ? "is set" : "is not set") << endl;
            Q_ASSERT(entry->boolValue() == !val);

            // Set to default
            entry->resetToDefault();
            Q_ASSERT(entry->boolValue() == false);   // that's the default
            Q_ASSERT(entry->isDirty());
            Q_ASSERT(!entry->isSet());
            config->sync(true);
            config->clear();

            // Check value
            entry = Kleo::getCryptoConfigEntry(config, "dirmngr", s_entryName);
            Q_ASSERT(!entry->isDirty());
            Q_ASSERT(!entry->isSet());
            cout << "quiet option reset to default: " << (entry->boolValue() ? "is set" : "is not set") << endl;
            Q_ASSERT(entry->boolValue() == false);

            // Reset old value
            entry->setBoolValue(val);
            Q_ASSERT(entry->isDirty());
            config->sync(true);

            cout << "quiet option reset to initial: " << (val ? "is set" : "is not set") << endl;
        } else {
            cout << "Entry 'dirmngr/" << s_entryName << "' not found" << endl;
        }
    }

    {
        // Static querying and setting of a single int option
        static const char *s_entryName = "ldaptimeout";
        QGpgME::CryptoConfigEntry *entry = Kleo::getCryptoConfigEntry(config, "dirmngr", s_entryName);
        if (entry) {
            // type of entry should be int (since 2.3) or uint (until 2.2)
            Q_ASSERT(entry->argType() == QGpgME::CryptoConfigEntry::ArgType_Int ||
                entry->argType() == QGpgME::CryptoConfigEntry::ArgType_UInt);
            const int initialValue = entry->argType() == QGpgME::CryptoConfigEntry::ArgType_Int ? entry->intValue() : static_cast<int>(entry->uintValue());
            cout << "LDAP timeout initially: " << initialValue << " seconds." << endl;

            // Test setting the option directly, then querying again
            //system( "echo 'ldaptimeout:0:101' | gpgconf --change-options dirmngr" );
            // Now let's do it with the C++ API instead
            if (entry->argType() == QGpgME::CryptoConfigEntry::ArgType_Int) {
                entry->setIntValue(101);
            } else {
                entry->setUIntValue(101);
            }
            Q_ASSERT(entry->isDirty());
            config->sync(true);

            // Clear cached values!
            config->clear();

            // Check new value
            {
                entry = Kleo::getCryptoConfigEntry(config, "dirmngr", s_entryName);
                Q_ASSERT(entry);
                const int newValue = entry->argType() == QGpgME::CryptoConfigEntry::ArgType_Int ? entry->intValue() : static_cast<int>(entry->uintValue());
                cout << "LDAP timeout now: " << newValue << " seconds." << endl;
                Q_ASSERT(newValue == 101);
            }

            // Set to default
            {
                entry->resetToDefault();
                const int defaultValue = entry->argType() == QGpgME::CryptoConfigEntry::ArgType_Int ? entry->intValue() : static_cast<int>(entry->uintValue());
                cout << "LDAP timeout reset to default, " << defaultValue << " seconds." << endl;
                Q_ASSERT(defaultValue == 15);
                Q_ASSERT(entry->isDirty());
                Q_ASSERT(!entry->isSet());
                config->sync(true);
                config->clear();
            }

            // Check value
            {
                entry = Kleo::getCryptoConfigEntry(config, "dirmngr", s_entryName);
                Q_ASSERT(!entry->isDirty());
                Q_ASSERT(!entry->isSet());
                const int defaultValue = entry->argType() == QGpgME::CryptoConfigEntry::ArgType_Int ? entry->intValue() : static_cast<int>(entry->uintValue());
                cout << "LDAP timeout reset to default, " << defaultValue << " seconds." << endl;
                Q_ASSERT(defaultValue == 15);
            }

            // Reset old value
            if (entry->argType() == QGpgME::CryptoConfigEntry::ArgType_Int) {
                entry->setIntValue(initialValue);
            } else {
                entry->setUIntValue(initialValue);
            }
            Q_ASSERT(entry->isDirty());
            config->sync(true);

            cout << "LDAP timeout reset to initial " << initialValue << " seconds." << endl;
        } else {
            cout << "Entry 'dirmngr/" << s_entryName << "' not found" << endl;
        }
    }

    {
        // Static querying and setting of a single string option
        static const char *s_entryName = "log-file";
        QGpgME::CryptoConfigEntry *entry = Kleo::getCryptoConfigEntry(config, "dirmngr", s_entryName);
        if (entry) {
            Q_ASSERT(entry->argType() == QGpgME::CryptoConfigEntry::ArgType_Path);
            QString val = entry->stringValue();
            cout << "Log-file initially: " << val.toLocal8Bit().constData() << endl;

            // Test setting the option, sync'ing, then querying again
            entry->setStringValue(QStringLiteral("/tmp/test:%e5ä"));
            Q_ASSERT(entry->isDirty());
            config->sync(true);

            // Let's see how it prints it
            system("gpgconf --list-options dirmngr | grep log-file");

            // Clear cached values!
            config->clear();

            // Check new value
            entry = Kleo::getCryptoConfigEntry(config, "dirmngr", s_entryName);
            Q_ASSERT(entry);
            Q_ASSERT(entry->argType() == QGpgME::CryptoConfigEntry::ArgType_Path);
            cout << "Log-file now: " << entry->stringValue().toLocal8Bit().constData() << endl;
            Q_ASSERT(entry->stringValue() == QStringLiteral("/tmp/test:%e5ä"));     // (or even with %e5 decoded)

            // Reset old value
#if 0
            QString arg(val);
            if (!arg.isEmpty()) {
                arg.prepend('"');
            }
            Q3CString sys;
            sys.sprintf("echo 'log-file:%s' | gpgconf --change-options dirmngr", arg.local8Bit().data());
            system(sys.data());
#endif
            entry->setStringValue(val);
            Q_ASSERT(entry->isDirty());
            config->sync(true);

            cout << "Log-file reset to initial " << val.toLocal8Bit().constData() << endl;
        } else {
            cout << "Entry 'dirmngr/" << s_entryName << "' not found" << endl;
        }
    }

    {
        // Static querying and setting of the keyserver list option
        static const char *s_entryName = "keyserver";
        QGpgME::CryptoConfigEntry *entry = Kleo::getCryptoConfigEntry(config, "gpgsm", s_entryName);
        if (entry) {
            Q_ASSERT(entry->argType() == QGpgME::CryptoConfigEntry::ArgType_LDAPURL);
            Q_ASSERT(entry->isList());
            const QList<QUrl> val = entry->urlValueList();
            cout << "URL list initially: ";
            for (const QUrl &url : val) {
                cout << url.toString().toLocal8Bit().constData() << ", ";
            }
            cout << endl;

            // Test setting the option, sync'ing, then querying again
            QList<QUrl> lst;
            lst << QUrl(QStringLiteral("ldap://a:389?b"));
            Q_ASSERT(lst[0].query() == QLatin1Char('b'));
            lst << QUrl(QStringLiteral("ldap://foo:389?a:b c"));
            Q_ASSERT(lst[1].query() == QStringLiteral("a:b c"));   // see, the space got _not_escaped
            lst << QUrl(QStringLiteral("ldap://server:389?a=b,c=DE"));
            Q_ASSERT(lst[2].query() == QStringLiteral("a=b,c=DE"));   // the query contains a literal ','
#if GPGMEPP_VERSION >= 0x11000 // 1.16.0
            lst << QUrl(QStringLiteral("ldap://foo:389?a#ldaps"));
            Q_ASSERT(lst[3].fragment() == QStringLiteral("ldaps"));
#endif
            //cout << " trying to set: " << lst.toStringList().join(", ").local8Bit() << endl;
            entry->setURLValueList(lst);
            Q_ASSERT(entry->isDirty());
            config->sync(true);

            // Let's see how it prints it
            system("gpgconf --list-options gpgsm | grep 'keyserver'");

            // Clear cached values!
            config->clear();

            // Check new value
            entry = Kleo::getCryptoConfigEntry(config, "gpgsm", s_entryName);
            Q_ASSERT(entry);
            Q_ASSERT(entry->argType() == QGpgME::CryptoConfigEntry::ArgType_LDAPURL);
            Q_ASSERT(entry->isList());
            // Get QUrl form
            const QList<QUrl> newlst = entry->urlValueList();
            cout << "URL list now: ";
            for (const QUrl &url : newlst) {
                cout << url.toString().toLocal8Bit().constData() << ", ";
            }
            cout << endl;
            Q_ASSERT(newlst.size() == lst.size());
            Q_ASSERT(newlst[0].url() == lst[0].url());
            Q_ASSERT(newlst[1].url() == lst[1].url());
            Q_ASSERT(newlst[2].url() == lst[2].url());
#if GPGMEPP_VERSION >= 0x11000 // 1.16.0
            Q_ASSERT(newlst[3].url() == lst[3].url());
#endif

            // Reset old value
            entry->setURLValueList(val);
            Q_ASSERT(entry->isDirty());
            config->sync(true);

            const QList<QUrl> resetList = entry->urlValueList();
            cout << "URL list reset to initial: ";
            for (const QUrl &url : resetList) {
                cout << url.toString().toLocal8Bit().constData() << ", ";
            }
            cout << endl;
        } else {
            cout << "Entry 'gpgsm/" << s_entryName << "' not found" << endl;
        }
    }

    cout << "Done." << endl;
}
