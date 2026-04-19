cmake_minimum_required(VERSION 3.16)
project(privacy_preserving_ffkm CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenFHE CONFIG REQUIRED)

add_library(ffkm_common context.cpp)
target_include_directories(ffkm_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ffkm_common PUBLIC OpenFHE::openfhe)

add_executable(cyber_aggregator cyber_aggregator.cpp)
target_link_libraries(cyber_aggregator PRIVATE ffkm_common)

add_executable(aadhaar_client aadhaar_client.cpp)
target_link_libraries(aadhaar_client PRIVATE ffkm_common)

add_executable(bank_client bank_client.cpp)
target_link_libraries(bank_client PRIVATE ffkm_common)

add_executable(telecom_client telecom_client.cpp)
target_link_libraries(telecom_client PRIVATE ffkm_common)
