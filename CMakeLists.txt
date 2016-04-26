cmake_minimum_required(VERSION 2.8.12)

project(libkleo)

find_package(ECM 5.19.0 CONFIG REQUIRED)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})
set(LIBRARY_NAMELINK)
include(GenerateExportHeader)
include(ECMSetupVersion)
include(ECMGenerateHeaders)
include(ECMGeneratePriFile)
include(ECMPackageConfigHelpers)
include(ECMSetupVersion)
include(FeatureSummary)
include(KDEInstallDirs)
include(KDECMakeSettings)
include(KDEFrameworkCompilerSettings NO_POLICY_SCOPE)
include(ECMQtDeclareLoggingCategory)
include(ECMAddTests)


set(KF5_VERSION "5.19.0")
set(LIBKLEO_LIB_VERSION "5.2.1")
set(QT_REQUIRED_VERSION "5.4.0")
set(GPGMEPP_LIB_VERSION "5.2.0")
set(KDEPIMTEXTEDIT_VERSION "5.2.0")
set(PIMCOMMON_LIB_VERSION "5.2.0")

find_package(Qt5 ${QT_REQUIRED_VERSION} CONFIG REQUIRED Widgets)
find_package(KF5I18n ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5Config ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5WidgetsAddons ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5Completion ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5WindowSystem ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5CoreAddons ${KF5_VERSION} CONFIG REQUIRED)
find_package(KF5Gpgmepp ${GPGMEPP_LIB_VERSION} CONFIG REQUIRED)
find_package(KF5PimTextEdit ${KDEPIMTEXTEDIT_VERSION} CONFIG)

find_package(Boost 1.34.0)
set_package_properties(Boost PROPERTIES DESCRIPTION "Boost C++ Libraries" URL "http://www.boost.org" TYPE REQUIRED PURPOSE "Boost is required for building most KDEPIM applications")



set_package_properties(KF5PimTextEdit PROPERTIES DESCRIPTION
                       "A textedit with PIM-specific features."
                       URL "https://projects.kde.org/projects/kde/pim/kpimtextedit"
                       TYPE OPTIONAL PURPOSE "Improved audit log viewer.")

ecm_setup_version(${LIBKLEO_LIB_VERSION} VARIABLE_PREFIX LIBKLEO
                        VERSION_HEADER "${CMAKE_CURRENT_BINARY_DIR}/libkleo_version.h"
                        PACKAGE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/KF5LibkleoConfigVersion.cmake"
                        SOVERSION 5
)

########### Targets ###########
add_definitions(-DQT_DISABLE_DEPRECATED_BEFORE=0)
remove_definitions( -DQT_NO_CAST_FROM_BYTEARRAY )
remove_definitions( -DQT_NO_CAST_FROM_ASCII )
remove_definitions( -DQT_NO_CAST_TO_ASCII )

########### CMake Config Files ###########
set(CMAKECONFIG_INSTALL_DIR "${KDE_INSTALL_CMAKEPACKAGEDIR}/KF5Libkleo")

ecm_configure_package_config_file(
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
feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
