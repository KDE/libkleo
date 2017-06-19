/*
    test_cryptoconfig.cpp

    This file is part of libkleopatra's test suite.
    Copyright (c) 2004 Klarälvdalens Datakonsult AB

    Libkleopatra is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License,
    version 2, as published by the Free Software Foundation.

    Libkleopatra is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    In addition, as a special exception, the copyright holders give
    permission to link the code of this program with any edition of
    the Qt library by Trolltech AS, Norway (or with modified versions
    of Qt that use the same license as Qt), and distribute linked
    combinations including the two.  You must obey the GNU General
    Public License in all respects for all of the code used other than
    Qt.  If you modify this file, you may extend this exception to
    your version of the file, but you are not obligated to do so.  If
    you do not wish to do so, delete this exception statement from
    your version.
*/

#include <qgpgme/qgpgmenewcryptoconfig.h>

#include <QCoreApplication>
#include <iostream>

using namespace std;
using namespace QGpgME;

#include <gpgme++/global.h>
#include <gpgme++/error.h>

#include <stdlib.h>

int main(int argc, char **argv)
{

    if (GpgME::initializeLibrary(0)) {
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
        static const QString s_groupName = QStringLiteral("Monitor");
        static const QString s_entryName = QStringLiteral("quiet");
        QGpgME::CryptoConfigEntry *entry = config->entry(QStringLiteral("dirmngr"), s_groupName, s_entryName);
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
            QGpgME::CryptoConfigEntry *entry = config->entry(QStringLiteral("dirmngr"), s_groupName, s_entryName);
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
            entry = config->entry(QStringLiteral("dirmngr"), s_groupName, s_entryName);
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
            cout << "Entry 'dirmngr/" << qPrintable(s_groupName) << "/" << qPrintable(s_entryName) << "' not found" << endl;
        }
    }

    {
        // Static querying and setting of a single int option
        static const QString s_groupName = QStringLiteral("LDAP");
        static const QString s_entryName = QStringLiteral("ldaptimeout");
        QGpgME::CryptoConfigEntry *entry = config->entry(QStringLiteral("dirmngr"), s_groupName, s_entryName);
        if (entry) {
            Q_ASSERT(entry->argType() == QGpgME::CryptoConfigEntry::ArgType_UInt);
            uint val = entry->uintValue();
            cout << "LDAP timeout initially: " << val << " seconds." << endl;

            // Test setting the option directly, then querying again
            //system( "echo 'ldaptimeout:0:101' | gpgconf --change-options dirmngr" );
            // Now let's do it with the C++ API instead
            entry->setUIntValue(101);
            Q_ASSERT(entry->isDirty());
            config->sync(true);

            // Clear cached values!
            config->clear();

            // Check new value
            QGpgME::CryptoConfigEntry *entry = config->entry(QStringLiteral("dirmngr"), s_groupName, s_entryName);
            Q_ASSERT(entry);
            Q_ASSERT(entry->argType() == QGpgME::CryptoConfigEntry::ArgType_UInt);
            cout << "LDAP timeout now: " << entry->uintValue() << " seconds." << endl;
            Q_ASSERT(entry->uintValue() == 101);

            // Set to default
            entry->resetToDefault();
            Q_ASSERT(entry->uintValue() == 100);
            Q_ASSERT(entry->isDirty());
            Q_ASSERT(!entry->isSet());
            config->sync(true);
            config->clear();

            // Check value
            entry = config->entry(QStringLiteral("dirmngr"), s_groupName, s_entryName);
            Q_ASSERT(!entry->isDirty());
            Q_ASSERT(!entry->isSet());
            cout << "LDAP timeout reset to default, " << entry->uintValue() << " seconds." << endl;
            Q_ASSERT(entry->uintValue() == 100);

            // Reset old value
            entry->setUIntValue(val);
            Q_ASSERT(entry->isDirty());
            config->sync(true);

            cout << "LDAP timeout reset to initial " << val << " seconds." << endl;
        } else {
            cout << "Entry 'dirmngr/" << qPrintable(s_groupName) << "/" << qPrintable(s_entryName) << "' not found" << endl;
        }
    }

    {
        // Static querying and setting of a single string option
        static const QString s_groupName = QStringLiteral("Debug");
        static const QString s_entryName = QStringLiteral("log-file");
        QGpgME::CryptoConfigEntry *entry = config->entry(QStringLiteral("dirmngr"), s_groupName, s_entryName);
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
            QGpgME::CryptoConfigEntry *entry = config->entry(QStringLiteral("dirmngr"), s_groupName, s_entryName);
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
            cout << "Entry 'dirmngr/" << qPrintable(s_groupName) << "/" << qPrintable(s_entryName) << "' not found" << endl;
        }
    }

    {
        // Static querying and setting of the LDAP URL list option
        static const QString s_groupName = QStringLiteral("LDAP");
        static const QString s_entryName = QStringLiteral("LDAP Server");
        QGpgME::CryptoConfigEntry *entry = config->entry(QStringLiteral("dirmngr"), s_groupName, s_entryName);
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
            lst << QUrl(QStringLiteral("ldap://foo:389?a:b c"));
            lst << QUrl(QStringLiteral("ldap://server:389?a=b,c=DE"));   // the query contains a literal ','
            //cout << " trying to set: " << lst.toStringList().join(", ").local8Bit() << endl;
            Q_ASSERT(lst[0].query() == QStringLiteral("b"));
            Q_ASSERT(lst[1].query() == QStringLiteral("a:b c"));   // see, the space got _not_escaped
            entry->setURLValueList(lst);
            Q_ASSERT(entry->isDirty());
            config->sync(true);

            // Let's see how it prints it
            system("gpgconf --list-options dirmngr | grep 'LDAP Server'");

            // Clear cached values!
            config->clear();

            // Check new value
            QGpgME::CryptoConfigEntry *entry = config->entry(QStringLiteral("dirmngr"), s_groupName, s_entryName);
            Q_ASSERT(entry);
            Q_ASSERT(entry->argType() == QGpgME::CryptoConfigEntry::ArgType_LDAPURL);
            Q_ASSERT(entry->isList());
            // Get QUrl form
            const QList<QUrl> newlst = entry->urlValueList();
            cout << "URL list now: ";
            for (const QUrl &url : newlst) {
                cout << url.toString().toLocal8Bit().constData() << endl;
            }
            cout << endl;
            Q_ASSERT(newlst.count() == 3);
            Q_ASSERT(newlst[0].url() == lst[0].url());
            Q_ASSERT(newlst[1].url() == lst[1].url());
            Q_ASSERT(newlst[2].url() == lst[2].url());

            // Reset old value
            entry->setURLValueList(val);
            Q_ASSERT(entry->isDirty());
            config->sync(true);

            cout << "URL list reset to initial: ";
            for (const QUrl &url : qAsConst(newlst)) {
                cout << url.toString().toLocal8Bit().constData() << ", ";
            }
            cout << endl;
        } else {
            cout << "Entry 'dirmngr/" << qPrintable(s_groupName) << "/" << qPrintable(s_entryName) << "' not found" << endl;
        }
    }

    cout << "Done." << endl;
}
