cmake_minimum_required(VERSION 3.31)
project(sha_2)

set(CMAKE_CXX_STANDARD 20)

include(FetchContent)
FetchContent_Declare(
		googletest
		URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()
add_executable(
		sha_2_test
		tests/sha_2.cpp
)
target_link_libraries(
		sha_2_test
		GTest::gtest_main
)
include(GoogleTest)
gtest_discover_tests(sha_2_test)

add_custom_target(
		copy_test_cases ALL
		COMMAND ${CMAKE_COMMAND} -E copy
		${CMAKE_SOURCE_DIR}/tests/test_cases.txt
		$<TARGET_FILE_DIR:sha_2_test>/test_cases.txt
		DEPENDS ${CMAKE_SOURCE_DIR}/tests/test_cases.txt
)
add_custom_target(
		copy_test_cases_double ALL
		COMMAND ${CMAKE_COMMAND} -E copy
		${CMAKE_SOURCE_DIR}/tests/test_cases_double.txt
		$<TARGET_FILE_DIR:sha_2_test>/test_cases_double.txt
		DEPENDS ${CMAKE_SOURCE_DIR}/tests/test_cases_double.txt
)
add_dependencies(sha_2_test copy_test_cases copy_test_cases_double)

add_executable(sha_2 main.cpp
		src/sha.h)
