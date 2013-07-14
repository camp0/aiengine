#include <string>
#include "SignatureManager.h"
#include "Signature.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE signaturetest 
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(signature_suite)

BOOST_AUTO_TEST_CASE (test1_signature)
{
	SignatureManager *sigmng = SignatureManager::getInstance();

	BOOST_CHECK(sigmng->getTotalSignatures()  ==0);
	BOOST_CHECK(sigmng->getTotalMatchingSignatures() == 0);
	BOOST_CHECK(sigmng->getMachtedSignature() == nullptr);
}

BOOST_AUTO_TEST_CASE (test2_signature)
{
        SignatureManager *sigmng = SignatureManager::getInstance();

	sigmng->addSignature("^hello");
        BOOST_CHECK(sigmng->getTotalSignatures()  == 1);
        BOOST_CHECK(sigmng->getTotalMatchingSignatures() == 0);
        BOOST_CHECK(sigmng->getMachtedSignature() == nullptr);
}


BOOST_AUTO_TEST_SUITE_END( )

