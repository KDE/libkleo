# SPDX-License-Identifier: CC0-1.0
# SPDX-FileCopyrightText: none
include(ECMMarkAsTest)

# Convenience macro to add kleo unit tests.
macro(add_kleo_test _source)
  set(_test ${_source})
  get_filename_component(_name ${_source} NAME_WE)
  add_executable(${_name} ${_test})
  ecm_mark_as_test(kleo-${_name})
  target_link_libraries(${_name} KPim6::Libkleo Qt::Widgets KF6::CoreAddons
      KF6::I18n KF6::WidgetsAddons)
endmacro()


add_kleo_test(test_cryptoconfig.cpp)
add_kleo_test(test_keyselectiondialog.cpp)
add_kleo_test(test_keygen.cpp test_keygen.h)
add_kleo_test(test_keylister.cpp test_keylister.h)
add_kleo_test(test_auditlog.cpp)
add_kleo_test(test_keyformailbox.cpp)
add_kleo_test(test_keyselectioncombo.cpp)
add_kleo_test(test_keyresolver.cpp)
