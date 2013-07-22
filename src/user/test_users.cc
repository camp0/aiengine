#include <string>
#include "../Cache.h"
#include "User.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE usertest 
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE (usercache) // name of the test suite is stringtest

BOOST_AUTO_TEST_CASE (test1_usercache)
{
	Cache<User>::CachePtr uc(new Cache<User>);

	BOOST_CHECK(uc->getTotal() == 0);
	BOOST_CHECK(uc->getTotalReleases() == 0);
	BOOST_CHECK(uc->getTotalAcquires() == 0);
	BOOST_CHECK(uc->getTotalFails() == 0);

	uc->create(1000);
	BOOST_CHECK(uc->getTotal() == 1000);
	uc->destroy(10000);
	BOOST_CHECK(uc->getTotal() == 0);
}

BOOST_AUTO_TEST_CASE (test2_usercache)
{
	Cache<User>::CachePtr uc(new Cache<User>);
     
        BOOST_CHECK(uc->getTotal() == 0);
        BOOST_CHECK(uc->getTotalReleases() == 0);
        BOOST_CHECK(uc->getTotalAcquires() == 0);
        BOOST_CHECK(uc->getTotalFails() == 0);

        uc->create(10);
        BOOST_CHECK(uc->getTotal() == 10);
        BOOST_CHECK(uc->getTotalReleases() == 0);
        BOOST_CHECK(uc->getTotalAcquires() == 0);
        BOOST_CHECK(uc->getTotalFails() == 0);

        uc->destroy(9);
        BOOST_CHECK(uc->getTotal() == 1);
        BOOST_CHECK(uc->getTotalFails() == 0);

        uc->destroy(9);
        BOOST_CHECK(uc->getTotal() == 0);
        BOOST_CHECK(uc->getTotalReleases() == 0);
        BOOST_CHECK(uc->getTotalAcquires() == 0);

        uc->create(1);
        User *u1 = uc->acquire();
        BOOST_CHECK(uc->getTotal() == 1);
        BOOST_CHECK(uc->getTotalReleases() == 0);
        BOOST_CHECK(uc->getTotalAcquires() == 1);
        BOOST_CHECK(uc->getTotalFails() == 0);

        User *u2 = uc->acquire();
        BOOST_CHECK(uc->getTotal() == 1);
        BOOST_CHECK(uc->getTotalReleases() == 0);
        BOOST_CHECK(uc->getTotalAcquires() == 1);
        BOOST_CHECK(uc->getTotalFails() == 1);
        BOOST_CHECK(u2 == nullptr);

        uc->release(u1);
        uc->destroy(1);
}

BOOST_AUTO_TEST_CASE (test3_usercache)
{
        Cache<User>::CachePtr uc(new Cache<User>);

        uc->create(10);

        User *u1 = uc->acquire();
        User *u2 = uc->acquire();
        User *u3 = uc->acquire();

        BOOST_CHECK(uc->getTotalOnCache() == 7);
        BOOST_CHECK(uc->getTotal() == 10);
        BOOST_CHECK(uc->getTotalReleases() == 0);
        BOOST_CHECK(uc->getTotalAcquires() == 3);
        BOOST_CHECK(uc->getTotalFails() == 0);
        BOOST_CHECK(u2 != u1);
        BOOST_CHECK(u1 != u3);

        uc->release(u1);
        uc->release(u2);
        uc->release(u3);
        BOOST_CHECK(uc->getTotalReleases() == 3);

        uc->destroy(uc->getTotal());

        BOOST_CHECK(uc->getTotal() == 0);
        BOOST_CHECK(uc->getTotalReleases() == 3);
        BOOST_CHECK(uc->getTotalAcquires() == 3);
        BOOST_CHECK(uc->getTotalFails() == 0);

        uc->create(1000);
        BOOST_CHECK(uc->getTotal() == 1000);
        uc->destroy(10000);
        BOOST_CHECK(uc->getTotal() == 0);
}

BOOST_AUTO_TEST_CASE (test4_usercache)
{
        Cache<User>::CachePtr uc(new Cache<User>);

        uc->create(1);

        User *u1 = uc->acquire();

        BOOST_CHECK(uc->getTotalOnCache() == 0);
        BOOST_CHECK(uc->getTotal() == 1);
        BOOST_CHECK(uc->getTotalReleases() == 0);
        BOOST_CHECK(uc->getTotalAcquires() == 1);
        BOOST_CHECK(uc->getTotalFails() == 0);

	u1->setId(10);
        uc->release(u1);
        BOOST_CHECK(uc->getTotalReleases() == 1);

	User *u2 = uc->acquire();
	BOOST_CHECK(u2->getId() == 0);
	BOOST_CHECK(u1 == u2);
	uc->release(u2);

}

BOOST_AUTO_TEST_SUITE_END( )

