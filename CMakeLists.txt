cmake_minimum_required(VERSION 3.16)
project(saml2-sp-c LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(LibXml2 REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)

add_library(saml2sp STATIC
  src/failure.cpp
  src/json.cpp
  src/crypto.cpp
  src/xml.cpp
  src/http.cpp
  src/protocol.cpp
  src/provider.cpp
  src/ssf.cpp
  src/c_api.cpp)
target_include_directories(saml2sp PUBLIC include PRIVATE src)
target_link_libraries(saml2sp PUBLIC OpenSSL::SSL OpenSSL::Crypto LibXml2::LibXml2 ZLIB::ZLIB Threads::Threads)

add_executable(saml2-sp src/cli_main.cpp)
target_include_directories(saml2-sp PRIVATE src)
target_link_libraries(saml2-sp PRIVATE saml2sp)

add_executable(saml-demo src/demo_main.cpp)
target_include_directories(saml-demo PRIVATE src)
target_link_libraries(saml-demo PRIVATE saml2sp)

add_executable(saml_tests tests/saml_tests.c)
target_link_libraries(saml_tests PRIVATE saml2sp)

add_executable(cpp_api_test tests/cpp_api_test.cpp)
target_link_libraries(cpp_api_test PRIVATE saml2sp)

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
  TestConfigureScriptSignals)
foreach(name ${SAML_CASES})
  add_test(NAME ${name} COMMAND saml_tests ${name})
  set_tests_properties(${name} PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} TIMEOUT 180)
endforeach()
add_test(NAME TestCppApiLinksTheSameLibrary COMMAND cpp_api_test)
set_tests_properties(TestCppApiLinksTheSameLibrary PROPERTIES TIMEOUT 60)
