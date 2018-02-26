cmake_minimum_required(VERSION 3.0)
set(PIM_VERSION "5.7.3")

project(libkleo VERSION ${PIM_VERSION})

set(KF5_VERSION "5.39.0")

find_package(ECM ${KF5_VERSION} CONFIG REQUIRED)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})
set(LIBRARY_NAMELINK)
include(GenerateExportHeader)
include(ECMSetupVersion)
include(ECMGenerateHeaders)
include(ECMGeneratePriFile)
include(CMakePackageConfigHelpers)
include(ECMSetupVersion)
include(FeatureSummary)
include(KDEInstallDirs)
include(KDECMakeSettings)
include(KDEFrameworkCompilerSettings NO_POLICY_SCOPE)
include(ECMQtDeclareLoggingCategory)
include(ECMAddTests)
include(ECMCoverageOption)


set(LIBKLEO_LIB_VERSION ${PIM_VERSION})
set(QT_REQUIRED_VERSION "5.8.0")
set(KDEPIMTEXTEDIT_VERSION "5.7.3")

find_package(Qt5 ${QT_REQUIRED_VERSION} CONFIG REQUIRED Widgets)
find_package(KF5I18n ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5Config ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5WidgetsAddons ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5Completion ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5WindowSystem ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5CoreAddons ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5Codecs ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5ItemModels ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5PimTextEdit ${KDEPIMTEXTEDIT_VERSION} CONFIG)

set(GPGMEPP_LIB_VERSION "1.7.1")
find_package(Gpgmepp ${GPGMEPP_LIB_VERSION})
set_package_properties(Gpgmepp PROPERTIES DESCRIPTION "GpgME++ Library" URL "http://www.gnupg.org" TYPE REQUIRED PURPOSE "GpgME++ is required for OpenPGP support")
find_package(QGpgme ${GPGMEPP_LIB_VERSION} CONFIG REQUIRED)


find_package(Boost 1.34.0)
set_package_properties(Boost PROPERTIES DESCRIPTION "Boost C++ Libraries" URL "http://www.boost.org" TYPE REQUIRED PURPOSE "Boost is required for building most KDEPIM applications")


set_package_properties(KF5PimTextEdit PROPERTIES DESCRIPTION
                       "A textedit with PIM-specific features."
                       URL "https://projects.kde.org/projects/kde/pim/kpimtextedit"
                       TYPE OPTIONAL PURPOSE "Improved audit log viewer.")

ecm_setup_version(PROJECT VARIABLE_PREFIX LIBKLEO
                        VERSION_HEADER "${CMAKE_CURRENT_BINARY_DIR}/libkleo_version.h"
                        PACKAGE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/KF5LibkleoConfigVersion.cmake"
                        SOVERSION 5
)

########### Targets ###########
add_definitions(-DQT_DISABLE_DEPRECATED_BEFORE=0)
#add_definitions(-DQT_DISABLE_DEPRECATED_BEFORE=0x060000)
remove_definitions( -DQT_NO_CAST_FROM_ASCII )
add_definitions(-DQT_NO_NARROWING_CONVERSIONS_IN_CONNECT)
add_definitions(-DQT_NO_URL_CAST_FROM_STRING)
add_definitions(-DQT_USE_QSTRINGBUILDER)


########### CMake Config Files ###########
set(CMAKECONFIG_INSTALL_DIR "${KDE_INSTALL_CMAKEPACKAGEDIR}/KF5Libkleo")

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/KF5LibkleoConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/KF5LibkleoConfig.cmake"
  INSTALL_DESTINATION  ${CMAKECONFIG_INSTALL_DIR}
)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/KF5LibkleoConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/KF5LibkleoConfigVersion.cmake"
  DESTINATION "${CMAKECONFIG_INSTALL_DIR}"
  COMPONENT Devel
)

install(EXPORT KF5LibkleoTargets DESTINATION "${CMAKECONFIG_INSTALL_DIR}" FILE KF5LibkleoTargets.cmake NAMESPACE KF5::)

install(FILES
   ${CMAKE_CURRENT_BINARY_DIR}/libkleo_version.h
  DESTINATION ${KDE_INSTALL_INCLUDEDIR_KF5} COMPONENT Devel
)



add_subdirectory(src)
install( FILES libkleo.renamecategories libkleo.categories DESTINATION ${KDE_INSTALL_CONFDIR} )
feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
