remove_definitions(-DQT_NO_CAST_FROM_ASCII)

include(ECMAddTests)

find_package(Qt5Test ${REQUIRED_QT_VERSION} CONFIG QUIET)

if(NOT Qt5Test_FOUND)
    message(STATUS "Qt5Test not found, autotests will not be built.")
    return()
endif()

ecm_add_test(
    flatkeylistmodeltest.cpp
    abstractkeylistmodeltest.cpp
    TEST_NAME flatkeylistmodeltest
    LINK_LIBRARIES KF5::Libkleo Qt::Test
)

ecm_add_test(
    hierarchicalkeylistmodeltest.cpp
    abstractkeylistmodeltest.cpp
    TEST_NAME hierarchicalkeylistmodeltest
    LINK_LIBRARIES KF5::Libkleo Qt::Test
)
