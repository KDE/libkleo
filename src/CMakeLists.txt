# SPDX-License-Identifier: CC0-1.0
# SPDX-FileCopyrightText: none
# target_include_directories does not handle empty include paths
include_directories(
    ${GPGME_INCLUDES}
)
add_definitions(-DTRANSLATION_DOMAIN=\"libkleopatra6\")

#add_definitions(-DQT_NO_CAST_FROM_ASCII)
#add_definitions(-DQT_NO_CAST_TO_ASCII)

kde_enable_exceptions()

add_definitions(-DGPGMEPP_ERR_SOURCE_DEFAULT=13) # 13 is GPG_ERR_SOURCE_KLEO, even if gpg-error's too old to know about

add_subdirectory(pics)
add_library(KPim6Libkleo)
add_library(KPim6::Libkleo ALIAS KPim6Libkleo)

########### next target ###############
target_sources(KPim6Libkleo PRIVATE
    pics/libkleopatra.qrc

    kleo/auditlogentry.cpp
    kleo/auditlogentry.h
    kleo/checksumdefinition.cpp
    kleo/checksumdefinition.h
    kleo/debug.cpp
    kleo/debug.h
    kleo/defaultkeyfilter.cpp
    kleo/defaultkeyfilter.h
    kleo/defaultkeygenerationjob.cpp
    kleo/defaultkeygenerationjob.h
    kleo/docaction.cpp kleo/docaction.h
    kleo/dn.cpp
    kleo/dn.h
    kleo/dnattributes.cpp
    kleo/dnattributes.h
    kleo/enum.cpp
    kleo/enum.h
    kleo/expirychecker.cpp
    kleo/expirychecker.h
    kleo/expirycheckerconfig.cpp
    kleo/expirycheckerconfig.h
    kleo/expirycheckersettings.cpp
    kleo/expirycheckersettings.h
    kleo/kconfigbasedkeyfilter.cpp
    kleo/kconfigbasedkeyfilter.h
    kleo/keyfilter.h
    kleo/keyfiltermanager.cpp
    kleo/keyfiltermanager.h
    kleo/keygroup.cpp
    kleo/keygroup.h
    kleo/keygroupconfig.cpp
    kleo/keygroupconfig.h
    kleo/keygroupimportexport.cpp
    kleo/keygroupimportexport.h
    kleo/keyresolver.cpp
    kleo/keyresolver.h
    kleo/keyresolvercore.cpp
    kleo/keyresolvercore.h
    kleo/keyserverconfig.cpp
    kleo/keyserverconfig.h
    kleo/kleoexception.cpp
    kleo/kleoexception.h
    kleo/oidmap.cpp
    kleo/oidmap.h
    kleo/predicates.h
    kleo/stl_util.h
    models/keycache.cpp
    models/keycache.h
    models/keycache_p.h
    models/keylist.h
    models/keylistmodel.cpp
    models/keylistmodel.h
    models/keylistmodelinterface.cpp
    models/keylistmodelinterface.h
    models/keylistsortfilterproxymodel.cpp
    models/keylistsortfilterproxymodel.h
    models/keyrearrangecolumnsproxymodel.cpp
    models/keyrearrangecolumnsproxymodel.h
    models/subkeylistmodel.cpp
    models/subkeylistmodel.h
    models/useridlistmodel.cpp
    models/useridlistproxymodel.cpp
    models/useridlistproxymodel.h
    models/useridlistmodel.h
    models/useridproxymodel.cpp
    models/useridproxymodel.h
    utils/algorithm.h
    utils/applicationpalettewatcher.cpp
    utils/applicationpalettewatcher.h
    utils/assuan.cpp
    utils/assuan.h
    utils/chrono.h
    utils/classify.cpp
    utils/classify.h
    utils/compat.cpp
    utils/compat.h
    utils/compliance.cpp
    utils/compliance.h
    utils/cryptoconfig.cpp
    utils/cryptoconfig.h
    utils/cryptoconfig_p.h
    utils/filesystemwatcher.cpp
    utils/filesystemwatcher.h
    utils/formatting.cpp
    utils/formatting.h
    utils/expiration.cpp
    utils/expiration.h
    utils/gnupg-registry.c
    utils/gnupg-registry.h
    utils/gnupg.cpp
    utils/gnupg.h
    utils/hex.cpp
    utils/hex.h
    utils/keyhelpers.cpp
    utils/keyhelpers.h
    utils/keyparameters.cpp
    utils/keyparameters.h
    utils/keyusage.h
    utils/qtstlhelpers.cpp
    utils/qtstlhelpers.h
    utils/scdaemon.cpp
    utils/scdaemon.h
    utils/stringutils.cpp
    utils/stringutils.h
    utils/systeminfo.cpp
    utils/systeminfo.h
    utils/test.cpp
    utils/test.h
    utils/validation.cpp
    utils/validation.h
    utils/multivalidator_p.h
    utils/multivalidator.cpp
)
ecm_qt_declare_logging_category(KPim6Libkleo HEADER libkleo_debug.h IDENTIFIER LIBKLEO_LOG CATEGORY_NAME org.kde.pim.libkleo
    DESCRIPTION "libkleo (kleo_core)"
    EXPORT LIBKLEO
)


target_sources(KPim6Libkleo PRIVATE
    ui/animatedexpander.cpp
    ui/animatedexpander.h
    ui/auditlogviewer.cpp
    ui/auditlogviewer.h
    ui/cryptoconfigentryreaderport.cpp
    ui/cryptoconfigentryreaderport_p.h
    ui/cryptoconfigmodule.cpp
    ui/cryptoconfigmodule.h
    ui/cryptoconfigmodule_p.h
    ui/directoryserviceswidget.cpp
    ui/directoryserviceswidget.h
    ui/dnattributeorderconfigwidget.cpp
    ui/dnattributeorderconfigwidget.h
    ui/editdirectoryservicedialog.cpp
    ui/editdirectoryservicedialog.h
    ui/errorlabel.cpp
    ui/errorlabel.h
    ui/filenamerequester.cpp
    ui/filenamerequester.h
    ui/formtextinput.cpp
    ui/formtextinput.h
    ui/messagebox.cpp
    ui/messagebox.h
    ui/nameandemailwidget.cpp
    ui/nameandemailwidget.h
    ui/openpgpcertificatecreationdialog.cpp
    ui/openpgpcertificatecreationdialog.h
    ui/treeview.cpp
    ui/treeview.h
    ui/treewidget.cpp
    ui/treewidget.h
    ui/progressbar.cpp
    ui/progressbar.h
    ui/progressdialog.cpp
    ui/progressdialog.h
    ui/readerportselection.cpp
    ui/readerportselection.h
)

ecm_qt_declare_logging_category(KPim6Libkleo HEADER kleo_ui_debug.h IDENTIFIER KLEO_UI_LOG CATEGORY_NAME org.kde.pim.kleo_ui
    DESCRIPTION "libkleo (kleo_ui)"
    OLD_CATEGORY_NAMES log_kleo_ui
    EXPORT LIBKLEO
)


target_sources(KPim6Libkleo PRIVATE    # make this a separate lib.
    ui/keyapprovaldialog.cpp
    ui/keyapprovaldialog.h
    ui/keylistview.cpp
    ui/keylistview.h
    ui/keyrequester.cpp
    ui/keyrequester.h
    ui/keyselectioncombo.cpp
    ui/keyselectioncombo.h
    ui/keyselectiondialog.cpp
    ui/keyselectiondialog.h
    ui/newkeyapprovaldialog.cpp
    ui/newkeyapprovaldialog.h
    ui/useridselectioncombo.cpp
    ui/useridselectioncombo.h
)

if(MINGW)
    # we do not care about different signedness of passed pointer arguments
    set_source_files_properties(utils/gnupg-registry.c PROPERTIES COMPILE_OPTIONS "-Wno-pointer-sign")
endif()

target_link_libraries(KPim6Libkleo PUBLIC Gpgmepp PRIVATE Qt::Widgets
                                                KF6::I18n
                                                KF6::Completion
                                                KF6::ConfigCore
                                                KF6::ColorScheme
                                                KF6::ConfigGui
                                                KF6::CoreAddons
                                                KF6::ItemModels
                                                KF6::WidgetsAddons
                                                KF6::Codecs
                                                LibGpgError::LibGpgError)

target_link_libraries(KPim6Libkleo PUBLIC QGpgmeQt6)
target_link_libraries(KPim6Libkleo PRIVATE Boost::headers)

if(COMPILE_WITH_UNITY_CMAKE_SUPPORT)
    set_target_properties(KPim6Libkleo PROPERTIES UNITY_BUILD ON)
endif()

ecm_generate_export_header(KPim6Libkleo
    BASE_NAME kleo
    VERSION ${PIM_VERSION}
    DEPRECATED_BASE_VERSION 0
    DEPRECATION_VERSIONS 5.23
)

if(WIN32)
    target_link_libraries(KPim6Libkleo ${GPGME_VANILLA_LIBRARIES})
endif()

set_target_properties(KPim6Libkleo PROPERTIES
    VERSION ${LIBKLEO_VERSION}
    SOVERSION ${LIBKLEO_SOVERSION}
    EXPORT_NAME Libkleo
)

install(TARGETS
    KPim6Libkleo
    EXPORT KPim6LibkleoTargets ${KDE_INSTALL_TARGETS_DEFAULT_ARGS}
)

target_include_directories(KPim6Libkleo INTERFACE "$<INSTALL_INTERFACE:${KDE_INSTALL_INCLUDEDIR}/KPim6/Libkleo>")
target_include_directories(KPim6Libkleo PUBLIC "$<BUILD_INTERFACE:${libkleo_SOURCE_DIR}/src>")

ecm_generate_headers(libkleo_CamelCase_HEADERS
    HEADER_NAMES
    AuditLogEntry
    ChecksumDefinition
    Debug
    DefaultKeyFilter
    DefaultKeyGenerationJob
    DocAction
    Dn
    DnAttributes
    Enum
    ExpiryChecker
    ExpiryCheckerConfig
    ExpiryCheckerSettings
    KConfigBasedKeyFilter
    KeyFilter
    KeyFilterManager
    KeyGroup
    KeyGroupConfig
    KeyGroupImportExport
    KeyResolver
    KeyResolverCore
    KeyserverConfig
    KleoException
    OidMap
    Predicates
    Stl_Util
    REQUIRED_HEADERS libkleo_HEADERS
    PREFIX Libkleo
    RELATIVE kleo
)

ecm_generate_headers(libkleo_CamelCase_models_HEADERS
    HEADER_NAMES
    KeyCache
    KeyList
    KeyListModel
    KeyListModelInterface
    KeyListSortFilterProxyModel
    KeyRearrangeColumnsProxyModel
    SubkeyListModel
    UserIDListModel
    UserIDListProxyModel
    UserIDProxyModel
    REQUIRED_HEADERS libkleo_models_HEADERS
    PREFIX Libkleo
    RELATIVE models
)

ecm_generate_headers(libkleo_CamelCase_utils_HEADERS
    HEADER_NAMES
    Algorithm
    ApplicationPaletteWatcher
    Assuan
    Chrono
    Classify
    Compat
    Compliance
    CryptoConfig
    Expiration
    FileSystemWatcher
    Formatting
    GnuPG
    Hex
    KeyHelpers
    KeyParameters
    KeyUsage
    QtStlHelpers
    SCDaemon
    StringUtils
    SystemInfo
    Test
    Validation
    REQUIRED_HEADERS libkleo_utils_HEADERS
    PREFIX Libkleo
    RELATIVE utils
)

ecm_generate_headers(libkleo_CamelCase_ui_HEADERS
    HEADER_NAMES
    AnimatedExpander
    AuditLogViewer
    CryptoConfigModule
    DNAttributeOrderConfigWidget
    DirectoryServicesWidget
    EditDirectoryServiceDialog
    ErrorLabel
    FormTextInput
    FileNameRequester
    KeyApprovalDialog
    KeyListView
    KeyRequester
    KeySelectionCombo
    KeySelectionDialog
    MessageBox
    NameAndEmailWidget
    TreeView
    TreeWidget
    NewKeyApprovalDialog
    OpenPGPCertificateCreationDialog
    ProgressDialog
    ReaderPortSelection
    UserIDSelectionCombo
    REQUIRED_HEADERS libkleo_ui_HEADERS
    PREFIX Libkleo
    RELATIVE ui
)

kconfig_add_kcfg_files(KPim6Libkleo
    kcfg/expirycheckerconfigbase.kcfgc
    kcfg/classifyconfig.kcfgc
    kcfg/openpgpcertificatecreationconfig.kcfgc
)

install(FILES
    ${libkleo_CamelCase_HEADERS}
    ${libkleo_CamelCase_models_HEADERS}
    ${libkleo_CamelCase_ui_HEADERS}
    ${libkleo_CamelCase_utils_HEADERS}
    DESTINATION ${KDE_INSTALL_INCLUDEDIR}/KPim6/Libkleo/Libkleo
    COMPONENT Devel
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/expirycheckerconfigbase.h
    ${CMAKE_CURRENT_BINARY_DIR}/kleo_export.h
    ${libkleo_HEADERS}
    ${libkleo_models_HEADERS}
    ${libkleo_ui_HEADERS}
    ${libkleo_utils_HEADERS}
    ${CMAKE_CURRENT_BINARY_DIR}/classifyconfig.h
    DESTINATION ${KDE_INSTALL_INCLUDEDIR}/KPim6/Libkleo/libkleo
    COMPONENT Devel
)

if(WIN32)
    install(FILES libkleopatrarc-win32.desktop DESTINATION ${KDE_INSTALL_CONFDIR} RENAME libkleopatrarc)
else ()
    install(FILES libkleopatrarc.desktop DESTINATION ${KDE_INSTALL_CONFDIR} RENAME libkleopatrarc)
endif()

if(BUILD_QCH)
    ecm_add_qch(
        KPim6Libkleo_QCH
        NAME KPim6Libkleo
        BASE_NAME KPim6Libkleo
        VERSION ${PIM_VERSION}
        ORG_DOMAIN org.kde
        SOURCES # using only public headers, to cover only public API
        ${libkleo_HEADERS}
        ${libkleo_models_HEADERS}
        ${libkleo_ui_HEADERS}
        ${libkleo_utils_HEADERS}
        #MD_MAINPAGE "${CMAKE_SOURCE_DIR}/README.md"
        #IMAGE_DIRS "${CMAKE_SOURCE_DIR}/docs/pics"
        LINK_QCHS
            Qt6Core_QCH
            Qt6Gui_QCH
            Qt6Widgets_QCH
        INCLUDE_DIRS
            ${CMAKE_CURRENT_BINARY_DIR}
        BLANK_MACROS
            KLEO_EXPORT
        TAGFILE_INSTALL_DESTINATION ${KDE_INSTALL_QTQCHDIR}
        QCH_INSTALL_DESTINATION ${KDE_INSTALL_QTQCHDIR}
        COMPONENT Devel
   )
endif()
