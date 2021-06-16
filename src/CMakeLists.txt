
# target_include_directories does not handle empty include paths
include_directories(${GPGME_INCLUDES})

add_definitions(-DTRANSLATION_DOMAIN=\"libkleopatra\")

#add_definitions( -DQT_NO_CAST_FROM_ASCII )
#add_definitions( -DQT_NO_CAST_TO_ASCII )

kde_enable_exceptions()

add_definitions( -DGPGMEPP_ERR_SOURCE_DEFAULT=13 ) # 13 is GPG_ERR_SOURCE_KLEO, even if gpg-error's too old to know about

add_subdirectory( pics )
if (BUILD_TESTING)
   add_subdirectory( tests )
endif()
add_library(KF5Libkleo)
add_library(KF5::Libkleo ALIAS KF5Libkleo)

########### next target ###############
target_sources(KF5Libkleo PRIVATE
   kleo/checksumdefinition.cpp
   kleo/debug.cpp
   kleo/defaultkeyfilter.cpp
   kleo/defaultkeygenerationjob.cpp
   kleo/dn.cpp
   kleo/enum.cpp
   kleo/kconfigbasedkeyfilter.cpp
   kleo/keyfiltermanager.cpp
   kleo/keygroup.cpp
   kleo/keyresolver.cpp
   kleo/keyresolvercore.cpp
   kleo/keyserverconfig.cpp
   kleo/kleoexception.cpp
   kleo/oidmap.cpp
   models/keycache.cpp
   models/keylistmodel.cpp
   models/keylistmodelinterface.cpp
   models/keylistsortfilterproxymodel.cpp
   models/keyrearrangecolumnsproxymodel.cpp
   models/subkeylistmodel.cpp
   models/useridlistmodel.cpp
   utils/filesystemwatcher.cpp
   utils/formatting.cpp
   utils/classify.cpp
   utils/gnupg.cpp
   utils/gnupg-registry.c
   utils/hex.cpp
   utils/compat.cpp
   utils/cryptoconfig.cpp
   utils/test.cpp
   )
ecm_qt_declare_logging_category(KF5Libkleo HEADER libkleo_debug.h IDENTIFIER LIBKLEO_LOG CATEGORY_NAME org.kde.pim.libkleo
        DESCRIPTION "libkleo (kleo_core)"
        EXPORT LIBKLEO
    )


target_sources(KF5Libkleo PRIVATE
   ui/dnattributeorderconfigwidget.cpp
   ui/kdhorizontalline.cpp
   ui/filenamerequester.cpp
   ui/messagebox.cpp
   ui/cryptoconfigmodule.cpp
   ui/directoryserviceswidget.cpp
   ui/progressbar.cpp
   ui/progressdialog.cpp
   ui/auditlogviewer.cpp
   ui/editdirectoryservicedialog.cpp
   )

ecm_qt_declare_logging_category(KF5Libkleo HEADER kleo_ui_debug.h IDENTIFIER KLEO_UI_LOG CATEGORY_NAME org.kde.pim.kleo_ui
        DESCRIPTION "libkleo (kleo_ui)"
        OLD_CATEGORY_NAMES log_kleo_ui
        EXPORT LIBKLEO
    )


target_sources(KF5Libkleo PRIVATE    # make this a separate lib.
    ui/keylistview.cpp
    ui/keyselectiondialog.cpp
    ui/keyrequester.cpp
    ui/keyapprovaldialog.cpp
    ui/newkeyapprovaldialog.cpp
    ui/keyselectioncombo.cpp
    )


target_link_libraries(KF5Libkleo PUBLIC QGpgme Gpgmepp PRIVATE Qt::Widgets
                                                KF5::I18n
                                                KF5::Completion
                                                KF5::ConfigCore
                                                KF5::CoreAddons
                                                KF5::WidgetsAddons
                                                KF5::ItemModels
                                                KF5::Codecs)

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



target_include_directories(KF5Libkleo PUBLIC "$<BUILD_INTERFACE:${libkleo_SOURCE_DIR}/src;${libkleo_BINARY_DIR}/src>")
target_include_directories(KF5Libkleo INTERFACE "$<INSTALL_INTERFACE:${KDE_INSTALL_INCLUDEDIR_KF5}/Libkleo/;${KDE_INSTALL_INCLUDEDIR_KF5}/libkleo>")

ecm_generate_headers(libkleo_CamelCase_HEADERS
  HEADER_NAMES
  ChecksumDefinition
  Debug
  DefaultKeyFilter
  DefaultKeyGenerationJob
  Dn
  Enum
  KConfigBasedKeyFilter
  KeyFilter
  KeyFilterManager
  KeyGroup
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
  Classify
  CryptoConfig
  FileSystemWatcher
  Formatting
  GnuPG
  Compat
  Test
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
  KDHorizontalLine
  KeyApprovalDialog
  NewKeyApprovalDialog
  KeyRequester
  KeySelectionCombo
  KeySelectionDialog
  MessageBox
  ProgressDialog
  REQUIRED_HEADERS libkleo_ui_HEADERS
  PREFIX Libkleo
  RELATIVE ui
)

ecm_generate_pri_file(BASE_NAME Libkleo
    LIB_NAME KF5Libkleo
    DEPS "QGpgme" FILENAME_VAR PRI_FILENAME INCLUDE_INSTALL_DIR ${KDE_INSTALL_INCLUDEDIR_KF5}/Libkleo
)


install(FILES
    ${libkleo_CamelCase_HEADERS}
    ${libkleo_CamelCase_models_HEADERS}
    ${libkleo_CamelCase_ui_HEADERS}
    ${libkleo_CamelCase_utils_HEADERS}
    DESTINATION ${KDE_INSTALL_INCLUDEDIR_KF5}/Libkleo
    COMPONENT Devel
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/kleo_export.h
    ${libkleo_HEADERS}
    ${libkleo_models_HEADERS}
    ${libkleo_ui_HEADERS}
    ${libkleo_utils_HEADERS}
    DESTINATION ${KDE_INSTALL_INCLUDEDIR_KF5}/libkleo
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
