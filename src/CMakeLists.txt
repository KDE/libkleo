
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

########### next target ###############
set(libkleo_core_SRCS
   kleo/checksumdefinition.cpp
   kleo/defaultkeyfilter.cpp
   kleo/defaultkeygenerationjob.cpp
   kleo/dn.cpp
   kleo/enum.cpp
   kleo/exception.cpp
   kleo/kconfigbasedkeyfilter.cpp
   kleo/keyfiltermanager.cpp
   models/keycache.cpp
   models/keylistmodel.cpp
   models/keylistsortfilterproxymodel.cpp
   models/keyrearrangecolumnsproxymodel.cpp
   models/modeltest.cpp
   models/subkeylistmodel.cpp
   models/useridlistmodel.cpp
   utils/filesystemwatcher.cpp
   utils/formatting.cpp
   utils/classify.cpp
   )
ecm_qt_declare_logging_category(libkleo_core_SRCS HEADER libkleo_debug.h IDENTIFIER LIBKLEO_LOG CATEGORY_NAME org.kde.pim.libkleo)

set(libkleo_ui_common_SRCS
   ui/dnattributeorderconfigwidget.cpp
   ui/kdhorizontalline.cpp
   ui/filenamerequester.cpp
   ui/messagebox.cpp
   ui/cryptoconfigmodule.cpp
   ui/cryptoconfigdialog.cpp
   ui/directoryserviceswidget.cpp
   ui/progressbar.cpp
   ui/progressdialog.cpp
   ui/auditlogviewer.cpp
   )
ecm_qt_declare_logging_category(libkleo_ui_common_SRCS HEADER kleo_ui_debug.h IDENTIFIER KLEO_UI_LOG CATEGORY_NAME org.kde.pim.kleo_ui)

set(libkleo_ui_SRCS    # make this a separate lib.
    ui/keylistview.cpp
    ui/keyselectiondialog.cpp
    ui/keyrequester.cpp
    ui/keyapprovaldialog.cpp
    ui/keyselectioncombo.cpp
    )

ki18n_wrap_ui(libkleo_ui_common_SRCS
    ui/directoryserviceswidget.ui
)

set(kleo_LIB_SRCS ${libkleo_core_SRCS} ${libkleo_ui_SRCS}
                                       ${libkleo_ui_common_SRCS})

set(kleo_LIB_LIBS PUBLIC QGpgme Gpgmepp PRIVATE Qt5::Widgets
                                                KF5::I18n
                                                KF5::Completion
                                                KF5::ConfigCore
                                                KF5::CoreAddons
                                                KF5::WindowSystem
                                                KF5::WidgetsAddons
                                                KF5::ItemModels
                                                KF5::Codecs)

if (KF5PimTextEdit_FOUND)
  add_definitions(-DHAVE_PIMTEXTEDIT)
  set(kleo_LIB_LIBS ${kleo_LIB_LIBS} PRIVATE KF5::PimTextEdit)
endif()

add_library(KF5Libkleo ${kleo_LIB_SRCS})
generate_export_header(KF5Libkleo BASE_NAME kleo)
add_library(KF5::Libkleo ALIAS KF5Libkleo)
if(WIN32)
target_link_libraries(KF5Libkleo ${kleo_LIB_LIBS}  ${GPGME_VANILLA_LIBRARIES} )
else()
target_link_libraries(KF5Libkleo ${kleo_LIB_LIBS} )
endif()

set_target_properties(KF5Libkleo PROPERTIES
    VERSION ${LIBKLEO_VERSION_STRING}
    SOVERSION ${LIBKLEO_SOVERSION}
    EXPORT_NAME Libkleo
)

install(TARGETS
    KF5Libkleo
    EXPORT KF5LibkleoTargets ${KF5_INSTALL_TARGETS_DEFAULT_ARGS} ${LIBRARY_NAMELINK}
)



target_include_directories(KF5Libkleo PUBLIC "$<BUILD_INTERFACE:${libkleo_SOURCE_DIR}/src;${libkleo_BINARY_DIR}/src>")
target_include_directories(KF5Libkleo INTERFACE "$<INSTALL_INTERFACE:${KDE_INSTALL_INCLUDEDIR_KF5}/Libkleo/;${KDE_INSTALL_INCLUDEDIR_KF5}/libkleo>")

ecm_generate_headers(libkleo_CamelCase_HEADERS
  HEADER_NAMES
  ChecksumDefinition
  DefaultKeyFilter
  DefaultKeyGenerationJob
  Dn
  Enum
  Exception
  KConfigBasedKeyFilter
  KeyFilter
  KeyFilterManager
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
  Classify
  FileSystemWatcher
  Formatting
  REQUIRED_HEADERS libkleo_utils_HEADERS
  PREFIX Libkleo
  RELATIVE utils
)

ecm_generate_headers(libkleo_CamelCase_ui_HEADERS
  HEADER_NAMES
  CryptoConfigDialog
  CryptoConfigModule
  DNAttributeOrderConfigWidget
  DirectoryServicesWidget
  FileNameRequester
  KDHorizontalLine
  KeyApprovalDialog
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
