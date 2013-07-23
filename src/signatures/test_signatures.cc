#include <string>
#include "SignatureManager.h"
#include "Signature.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE signaturetest 
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(signature_suite)

BOOST_AUTO_TEST_CASE (test1_signature)
{
	SignatureManagerPtr sigmng = SignatureManagerPtr( new SignatureManager());

	BOOST_CHECK(sigmng->getTotalSignatures()  ==0);
	BOOST_CHECK(sigmng->getTotalMatchingSignatures() == 0);
	BOOST_CHECK(sigmng->getMachtedSignature() == nullptr);
}

BOOST_AUTO_TEST_CASE (test2_signature)
{
	SignatureManagerPtr sigmng = SignatureManagerPtr( new SignatureManager());

	sigmng->addSignature("^hello");
        BOOST_CHECK(sigmng->getTotalSignatures()  == 1);
        BOOST_CHECK(sigmng->getTotalMatchingSignatures() == 0);
        BOOST_CHECK(sigmng->getMachtedSignature() == nullptr);

	std::string cad("hello world");
	bool value = false;
	unsigned const char *buffer = reinterpret_cast<const unsigned char*>(cad.c_str());

	sigmng->evaluate(buffer,&value);
	BOOST_CHECK(value == true);
	BOOST_CHECK(sigmng->getMachtedSignature() != nullptr);
        BOOST_CHECK(sigmng->getTotalMatchingSignatures() == 1);
}

BOOST_AUTO_TEST_CASE (test3_signature)
{
        SignatureManagerPtr sigmng = SignatureManagerPtr( new SignatureManager());
	Signature sig("some hex");

        sigmng->addSignature(sig);
        BOOST_CHECK(sigmng->getTotalSignatures()  == 1);
        BOOST_CHECK(sigmng->getTotalMatchingSignatures() == 0);
        BOOST_CHECK(sigmng->getMachtedSignature() == nullptr);

        std::string cad("hello world im not a hex, but some hex yes");
        bool value = false;
        unsigned const char *buffer = reinterpret_cast<const unsigned char*>(cad.c_str());

        sigmng->evaluate(buffer,&value);
        BOOST_CHECK(value == true);
        BOOST_CHECK(sigmng->getMachtedSignature() != nullptr);
        BOOST_CHECK(sigmng->getMachtedSignature().get() != nullptr);
        BOOST_CHECK(sigmng->getTotalMatchingSignatures() == 1);

	// Shared ptr and sig are stored on different places but should have the same regex
	BOOST_CHECK(sig.getExpression().compare(sigmng->getMachtedSignature()->getExpression())== 0);
}


BOOST_AUTO_TEST_SUITE_END( )

