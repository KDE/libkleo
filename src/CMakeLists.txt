# SPDX-License-Identifier: CC0-1.0
# SPDX-FileCopyrightText: none
# target_include_directories does not handle empty include paths
include_directories(
    ${Boost_INCLUDE_DIRS}
    ${GPGME_INCLUDES}
)

add_definitions(-DTRANSLATION_DOMAIN=\"libkleopatra\")

#add_definitions( -DQT_NO_CAST_FROM_ASCII )
#add_definitions( -DQT_NO_CAST_TO_ASCII )

kde_enable_exceptions()

add_definitions( -DGPGMEPP_ERR_SOURCE_DEFAULT=13 ) # 13 is GPG_ERR_SOURCE_KLEO, even if gpg-error's too old to know about

add_subdirectory( pics )
add_library(KF5Libkleo)
add_library(KF5::Libkleo ALIAS KF5Libkleo)

########### next target ###############
target_sources(KF5Libkleo PRIVATE
   kleo/checksumdefinition.cpp
   kleo/checksumdefinition.h
   kleo/debug.cpp
   kleo/debug.h
   kleo/defaultkeyfilter.cpp
   kleo/defaultkeyfilter.h
   kleo/defaultkeygenerationjob.cpp
   kleo/defaultkeygenerationjob.h
   kleo/docaction.cpp
   kleo/dn.cpp
   kleo/dn.h
   kleo/enum.cpp
   kleo/enum.h
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
   models/useridlistmodel.h
   utils/algorithm.h
   utils/assuan.cpp
   utils/assuan.h
   utils/classify.cpp
   utils/classify.h
   utils/compat.cpp
   utils/compat.h
   utils/cryptoconfig.cpp
   utils/cryptoconfig.h
   utils/cryptoconfig_p.h
   utils/filesystemwatcher.cpp
   utils/filesystemwatcher.h
   utils/formatting.cpp
   utils/formatting.h
   utils/gnupg-registry.c
   utils/gnupg-registry.h
   utils/gnupg.cpp
   utils/gnupg.h
   utils/hex.cpp
   utils/hex.h
   utils/keyhelpers.cpp
   utils/keyhelpers.h
   utils/qtstlhelpers.cpp
   utils/qtstlhelpers.h
   utils/scdaemon.cpp
   utils/scdaemon.h
   utils/stringutils.cpp
   utils/stringutils.h
   utils/test.cpp
   utils/test.h
   utils/uniquelock.cpp
   utils/uniquelock.h
   )
ecm_qt_declare_logging_category(KF5Libkleo HEADER libkleo_debug.h IDENTIFIER LIBKLEO_LOG CATEGORY_NAME org.kde.pim.libkleo
        DESCRIPTION "libkleo (kleo_core)"
        EXPORT LIBKLEO
    )


target_sources(KF5Libkleo PRIVATE
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
   ui/filenamerequester.cpp
   ui/filenamerequester.h
   ui/messagebox.cpp
   ui/messagebox.h
   ui/progressbar.cpp
   ui/progressbar.h
   ui/progressdialog.cpp
   ui/progressdialog.h
   ui/readerportselection.cpp
   ui/readerportselection.h
)

ecm_qt_declare_logging_category(KF5Libkleo HEADER kleo_ui_debug.h IDENTIFIER KLEO_UI_LOG CATEGORY_NAME org.kde.pim.kleo_ui
        DESCRIPTION "libkleo (kleo_ui)"
        OLD_CATEGORY_NAMES log_kleo_ui
        EXPORT LIBKLEO
    )


target_sources(KF5Libkleo PRIVATE    # make this a separate lib.
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
    )


target_link_libraries(KF5Libkleo PUBLIC QGpgme Gpgmepp PRIVATE Qt${QT_MAJOR_VERSION}::Widgets
                                                KF5::I18n
                                                KF5::Completion
                                                KF5::ConfigCore
                                                KF5::CoreAddons
                                                KF5::WidgetsAddons
                                                KF5::ItemModels
                                                KF5::Codecs)
if (QT_MAJOR_VERSION STREQUAL "6")
    target_link_libraries(KF5Libkleo PRIVATE Qt6Core5Compat)
endif()
# Boost::headers may not be available for old versions of Boost
if (TARGET Boost::headers)
  target_link_libraries(KF5Libkleo PRIVATE Boost::headers)
endif()

if (KF5PimTextEdit_FOUND)
  add_definitions(-DHAVE_PIMTEXTEDIT)
  target_link_libraries(KF5Libkleo PRIVATE KF5::PimTextEdit)
endif()

if (COMPILE_WITH_UNITY_CMAKE_SUPPORT)
    set_target_properties(KF5Libkleo PROPERTIES UNITY_BUILD ON)
endif()
generate_export_header(KF5Libkleo BASE_NAME kleo)
if(WIN32)
    target_link_libraries(KF5Libkleo ${GPGME_VANILLA_LIBRARIES} )
endif()

set_target_properties(KF5Libkleo PROPERTIES
    VERSION ${LIBKLEO_VERSION}
    SOVERSION ${LIBKLEO_SOVERSION}
    EXPORT_NAME Libkleo
)

install(TARGETS
    KF5Libkleo
    EXPORT KF5LibkleoTargets ${KF5_INSTALL_TARGETS_DEFAULT_ARGS}
)

target_include_directories(KF5Libkleo INTERFACE "$<INSTALL_INTERFACE:${KDE_INSTALL_INCLUDEDIR_KF}/Libkleo>")
target_include_directories(KF5Libkleo PUBLIC "$<BUILD_INTERFACE:${libkleo_SOURCE_DIR}/src;${libkleo_BINARY_DIR}/src>")

ecm_generate_headers(libkleo_CamelCase_HEADERS
  HEADER_NAMES
  ChecksumDefinition
  Debug
  DefaultKeyFilter
  DefaultKeyGenerationJob
  DocAction
  Dn
  Enum
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
  REQUIRED_HEADERS libkleo_models_HEADERS
  PREFIX Libkleo
  RELATIVE models
)

ecm_generate_headers(libkleo_CamelCase_utils_HEADERS
  HEADER_NAMES
  Algorithm
  Assuan
  Classify
  Compat
  CryptoConfig
  FileSystemWatcher
  Formatting
  GnuPG
  Hex
  KeyHelpers
  QtStlHelpers
  SCDaemon
  StringUtils
  Test
  UniqueLock
  REQUIRED_HEADERS libkleo_utils_HEADERS
  PREFIX Libkleo
  RELATIVE utils
)

ecm_generate_headers(libkleo_CamelCase_ui_HEADERS
  HEADER_NAMES
  CryptoConfigModule
  DNAttributeOrderConfigWidget
  DirectoryServicesWidget
  EditDirectoryServiceDialog
  FileNameRequester
  KeyApprovalDialog
  KeyRequester
  KeySelectionCombo
  KeySelectionDialog
  MessageBox
  NewKeyApprovalDialog
  ProgressDialog
  ReaderPortSelection
  REQUIRED_HEADERS libkleo_ui_HEADERS
  PREFIX Libkleo
  RELATIVE ui
)

ecm_generate_pri_file(BASE_NAME Libkleo
    LIB_NAME KF5Libkleo
    DEPS "QGpgme" FILENAME_VAR PRI_FILENAME INCLUDE_INSTALL_DIR ${KDE_INSTALL_INCLUDEDIR_KF}/Libkleo
)


install(FILES
    ${libkleo_CamelCase_HEADERS}
    ${libkleo_CamelCase_models_HEADERS}
    ${libkleo_CamelCase_ui_HEADERS}
    ${libkleo_CamelCase_utils_HEADERS}
    DESTINATION ${KDE_INSTALL_INCLUDEDIR_KF}/Libkleo/Libkleo
    COMPONENT Devel
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/kleo_export.h
    ${libkleo_HEADERS}
    ${libkleo_models_HEADERS}
    ${libkleo_ui_HEADERS}
    ${libkleo_utils_HEADERS}
    DESTINATION ${KDE_INSTALL_INCLUDEDIR_KF}/Libkleo/libkleo
    COMPONENT Devel
)
install(FILES
    ${PRI_FILENAME}
    DESTINATION ${ECM_MKSPECS_INSTALL_DIR})


if ( WIN32 )
    install ( FILES libkleopatrarc-win32.desktop DESTINATION ${KDE_INSTALL_CONFDIR} RENAME libkleopatrarc )
else ()
    install ( FILES libkleopatrarc.desktop DESTINATION ${KDE_INSTALL_CONFDIR} RENAME libkleopatrarc )
endif ()

if (BUILD_QCH)
    ecm_add_qch(
        KF5Libkleo_QCH
        NAME KF5Libkleo
        BASE_NAME KF5Libkleo
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
            Qt5Core_QCH
            Qt5Gui_QCH
            Qt5Widgets_QCH
        INCLUDE_DIRS
            ${CMAKE_CURRENT_BINARY_DIR}
        BLANK_MACROS
            KLEO_EXPORT
        TAGFILE_INSTALL_DESTINATION ${KDE_INSTALL_QTQCHDIR}
        QCH_INSTALL_DESTINATION ${KDE_INSTALL_QTQCHDIR}
        COMPONENT Devel
    )
endif()
