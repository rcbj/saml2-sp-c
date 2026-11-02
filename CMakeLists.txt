cmake_minimum_required(VERSION 3.16)

# The version is VERSION's, so the library, the package and the release tag agree.
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" IYA_SAML_VERSION)
string(STRIP "${IYA_SAML_VERSION}" IYA_SAML_VERSION)
project(saml2-sp-c VERSION ${IYA_SAML_VERSION} LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# On when this is the top-level project (a checkout, the Docker test stage); a package
# build (a Conan recipe, add_subdirectory) turns them off and gets the library alone.
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  set(IYA_SAML_TOP_LEVEL ON)
else()
  set(IYA_SAML_TOP_LEVEL OFF)
endif()
option(IYA_SAML_BUILD_TESTS "Build the tests" ${IYA_SAML_TOP_LEVEL})
option(IYA_SAML_BUILD_PROGRAMS "Build the demo and the command-line programs" ${IYA_SAML_TOP_LEVEL})

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(LibXml2 REQUIRED)
find_package(ZLIB REQUIRED)

# Static or shared as BUILD_SHARED_LIBS says (static when it is unset).
add_library(iya_saml
  src/failure.cpp
  src/json.cpp
  src/crypto.cpp
  src/xml.cpp
  src/http.cpp
  src/protocol.cpp
  src/provider.cpp
  src/ssf.cpp
  src/c_api.cpp)
add_library(iya::saml ALIAS iya_saml)
target_include_directories(iya_saml
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(iya_saml PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads LibXml2::LibXml2 ZLIB::ZLIB)
# The C++ headers need C++17; a consumer gets that from the target.
target_compile_features(iya_saml PUBLIC cxx_std_17)
set_target_properties(iya_saml PROPERTIES
  EXPORT_NAME saml
  POSITION_INDEPENDENT_CODE ON
  VERSION ${PROJECT_VERSION}
  # 0.x: every minor version may break the ABI.
  SOVERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR})

# The library, its public headers (include/ holds nothing else), and a CMake package:
#   find_package(iya_saml REQUIRED)
#   target_link_libraries(app PRIVATE iya::saml)
install(TARGETS iya_saml EXPORT iya_samlTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT iya_samlTargets NAMESPACE iya:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/iya_saml)
configure_package_config_file(cmake/iya_samlConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/iya_samlConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/iya_saml)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/iya_samlConfigVersion.cmake
  COMPATIBILITY SameMinorVersion)
install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/iya_samlConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/iya_samlConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/iya_saml)

if(IYA_SAML_BUILD_PROGRAMS OR IYA_SAML_BUILD_TESTS)
add_executable(saml2-sp src/cli_main.cpp)
target_include_directories(saml2-sp PRIVATE src)
target_link_libraries(saml2-sp PRIVATE iya_saml)
add_executable(saml-demo src/demo_main.cpp)
target_include_directories(saml-demo PRIVATE src)
target_link_libraries(saml-demo PRIVATE iya_saml)
endif()

if(IYA_SAML_BUILD_TESTS)
add_executable(saml_tests tests/saml_tests.c)
target_link_libraries(saml_tests PRIVATE iya_saml)
add_executable(saml_trust_tests tests/trust.c)
target_link_libraries(saml_trust_tests PRIVATE iya_saml OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
add_executable(cpp_api_test tests/cpp_api_test.cpp)
target_link_libraries(cpp_api_test PRIVATE iya_saml)
enable_testing()
set(SAML_CASES
  TestRefusesAConfigurationWithoutAKeyOrWithAnotherCertificate
  TestReadsTheIdentityProviderFromItsMetadata
  TestWritesMetadataWithASignedRequestsKeyAndTheAcsOnAllThreeBindings
  TestOmitsSignalsUnlessItIsFalse
  TestRecordsSignalsFalseAndStillResolvesTheSamlFields
  TestRefusesASignalsValueThatIsNotTrueOrFalse
  TestRedirectAuthnRequestIsDeflatedAndSigned
  TestPostAuthnRequestIsAnEnvelopedSignatureInAForm
  TestSubjectHintFollowsTheIssuerAndItsSignature
  TestRefusesARelayStateOver80Bytes
  TestSignedResponseAndSignedAssertion
  TestAcceptsASignedAssertionInAnUnsignedResponse
  TestRefusesAnUnsignedAssertionByDefault
  TestRefusesAResponseWithNothingSigned
  TestRefusesAnAssertionAlteredAfterItWasSigned
  TestRefusesASignatureByAnotherKey
  TestIsNotFooledBySignatureWrapping
  TestRefusesAResponseForAnotherAudienceAcsOrThatHasExpired
  TestRefusesAnAnswerToAnotherRequestAndAnUnsolicitedOne
  TestRefusesTheSameAssertionTwice
  TestReportsANonSuccessStatus
  TestRefusesADoctype
  TestDecryptsAnEncryptedAssertion
  TestRefusesAPlaintextAssertionWhenEncryptionIsRequired
  TestRefusesAnEncryptedAssertionWhoseCiphertextWasAltered
  TestDecryptsAnEncryptedAttribute
  TestRedirectResponseVerifiesTheQuerySignature
  TestRefusesAQuerySignatureByAnotherKeyAndAChangedRelayState
  TestResolvesTheArtifact
  TestAcceptsTheArtifactOnAPostAndFailsWhenAlreadyUsed
  TestRefusesAnArtifactFromAnotherIdentityProvider
  TestRefusesARequestWithNoSamlMessage
  TestParseXMLHelperStaysAvailable
  TestVerifiesASetAgainstTheJwks
  TestReadsComplexIssSubAndEmailSubjects
  TestNamesAllEightCaepAndFourteenRiscEventTypes
  TestSharedSignals
  TestRefusesATransmitterWithoutPollDelivery
  TestStopWaitsForAnInFlightPoll
  TestConfigureScriptSignals
  TestLiveStatusReportsTheSignInWithoutTokens)
foreach(name ${SAML_CASES})
  add_test(NAME ${name} COMMAND saml_tests ${name} $<TARGET_FILE:saml-demo>)
  set_tests_properties(${name} PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} TIMEOUT 180)
endforeach()
set(TRUST_CASES
  TestIdpCaChainIsTheTrustStore
  TestAForgedLeafBeforeTheRealCaIsRefused
  TestHostNameIsChecked
  TestConfigureWritesTheWholeChain)
foreach(name ${TRUST_CASES})
  add_test(NAME ${name} COMMAND saml_trust_tests ${name})
  set_tests_properties(${name} PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} TIMEOUT 180)
endforeach()
add_test(NAME TestCppApiLinksTheSameLibrary COMMAND cpp_api_test)
set_tests_properties(TestCppApiLinksTheSameLibrary PROPERTIES TIMEOUT 60)
endif()
