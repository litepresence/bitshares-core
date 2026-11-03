file(GLOB COMMON_SOURCES "common/*.cpp")
file(GLOB COMMON_HEADERS "common/*.hpp")

add_library( database_fixture
             ${COMMON_SOURCES}
             ${COMMON_HEADERS}
           )
target_link_libraries( database_fixture PUBLIC graphene_es_objects graphene_app graphene_egenesis_none )
target_include_directories( database_fixture
                            PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/common" )

find_package( Gperftools QUIET )
if( GPERFTOOLS_FOUND )
    message( STATUS "Found gperftools; compiling tests with TCMalloc")
    list( APPEND PLATFORM_SPECIFIC_LIBS tcmalloc )
endif()

file(GLOB UNIT_TESTS "tests/*.cpp")
add_executable( chain_test ${UNIT_TESTS} )
target_link_libraries( chain_test database_fixture
                       graphene_witness graphene_wallet graphene_app ${PLATFORM_SPECIFIC_LIBS} )
# G2-3: wallet printer unit tests include the wallet-internal
# operation_printer.hpp/wallet_api_impl.hpp (same-dir quoted includes resolve
# via this path; public wallet headers stay under wallet/include).
target_include_directories( chain_test PRIVATE "${CMAKE_SOURCE_DIR}/libraries/wallet" )
if(MSVC)
  set_source_files_properties( tests/serialization_tests.cpp PROPERTIES COMPILE_FLAGS "/bigobj" )
  set_source_files_properties( tests/common/database_fixture.cpp PROPERTIES COMPILE_FLAGS "/bigobj" )
endif(MSVC)

file(GLOB PERFORMANCE_TESTS "performance/*.cpp")
add_executable( performance_test ${PERFORMANCE_TESTS} )
target_link_libraries( performance_test database_fixture ${PLATFORM_SPECIFIC_LIBS} )

file(GLOB APP_SOURCES "app/*.cpp")
add_executable( app_test ${APP_SOURCES} )
target_link_libraries( app_test graphene_app graphene_egenesis_none
                       ${PLATFORM_SPECIFIC_LIBS} )

file(GLOB CLI_SOURCES "cli/*.cpp")
add_executable( cli_test ${CLI_SOURCES} )
if(WIN32)
   list(APPEND PLATFORM_SPECIFIC_LIBS ws2_32)
endif()
target_link_libraries( cli_test graphene_wallet graphene_app graphene_egenesis_none
                       ${PLATFORM_SPECIFIC_LIBS} )
if(MSVC)
  set_source_files_properties( cli/main.cpp PROPERTIES COMPILE_FLAGS "/bigobj" )
endif(MSVC)

file(GLOB ES_SOURCES "elasticsearch/*.cpp")
add_executable( es_test ${ES_SOURCES} )
target_link_libraries( es_test database_fixture ${PLATFORM_SPECIFIC_LIBS} )
                       
add_subdirectory( generate_empty_blocks )
