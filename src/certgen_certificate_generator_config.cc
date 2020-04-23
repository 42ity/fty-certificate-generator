/*  =========================================================================
    certgen_certificate_generator_config - class description

    Copyright (C) 2014 - 2020 Eaton

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    =========================================================================
*/

/*
@header
    certgen_certificate_generator_config -
@discuss
@end
*/

#include "certgen_certificate_generator_config.h"

//  Structure of our class
namespace certgen
{
    void CertificateGeneratorConfig::load(const cxxtools::SerializationInfo& si)
    {
        si.getMember("version")     >>= m_version;
        si.getMember("key")         >>= m_keyConf;
        si.getMember("certificate") >>= m_certConf;
        si.getMember("storage")     >>= m_storageConf;
    }

    void operator>>= (const cxxtools::SerializationInfo& si, CertificateGeneratorConfig & config)
    {
        config.load(si);
    }

    std::ostream& operator<<(std::ostream& os, const CertificateGeneratorConfig & c)
    {
        os << "Version: " << c.version() << std::endl;
        os << c.keyConf() << std::endl;
        // os << c.certConf() << std::endl;
        os << c.storageConf() << std::endl;

        return os;
    }
} // namescpace certgen

//  --------------------------------------------------------------------------
//  Self test of this class
#define SELFTEST_DIR_RO "src/selftest-ro"
#define SELFTEST_DIR_RW "src/selftest-rw"

// color output definition for test function
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#include <cassert>
#include <iostream>
#include <fstream>
#include <vector>

void
certgen_certificate_generator_config_test (bool verbose)
{
    //  @selftest
    //  Simple create/destroy test

    printf (" * certgen_certificate_generator_config: ");

    std::vector<std::pair<std::string, bool>> testsResults;

    std::string testNumber;
    std::string testName;

    //Next test
    testNumber = "1.1";
    testName = "Read configuration (key type RSA)-> success case";
    printf ("\n----------------------------------------------------------------"
            "-------\n");
    {
        printf (" *=>  Test #%s %s\n", testNumber.c_str (), testName.c_str ());

        try {
            //Do the test here. If error throw expections
            using namespace certgen;

            std::string configFilePath(SELFTEST_DIR_RO + std::string("/test_rsa.cfg"));

            std::ifstream configFile(configFilePath);

            std::stringstream configJson;
            configJson << configFile.rdbuf();
            configFile.close();

            cxxtools::SerializationInfo configSi;
            cxxtools::JsonDeserializer deserializer(configJson);
            deserializer.deserialize(configSi);

            CertificateGeneratorConfig conf;

            configSi >>= conf;

            printf (" *<=  Test #%s > OK\n", testNumber.c_str ());
            testsResults.emplace_back (" Test #" + testNumber + " " + testName, true);
        }
        catch (const std::exception &e) {
            printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
            printf ("Error: %s\n", e.what ());
            testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
        }
    }

    printf ("OK\n");

    //Next test
    testNumber = "1.2";
    testName = "Read configuration (key type RSA)-> error case";
    printf ("\n----------------------------------------------------------------"
            "-------\n");
    {
        printf (" *=>  Test #%s %s\n", testNumber.c_str (), testName.c_str ());

        try {
            //Do the test here. If error throw expections
            using namespace certgen;

            std::string configFilePath(SELFTEST_DIR_RO + std::string("/test_rsa_err.cfg"));

            std::ifstream configFile(configFilePath);

            std::stringstream configJson;
            configJson << configFile.rdbuf();
            configFile.close();

            cxxtools::SerializationInfo configSi;
            cxxtools::JsonDeserializer deserializer(configJson);
            deserializer.deserialize(configSi);

            CertificateGeneratorConfig conf;

            configSi >>= conf;

            printf (" *<=  Test #%s > OK\n", testNumber.c_str ());
            testsResults.emplace_back (" Test #" + testNumber + " " + testName, true);
        }
        catch(const std::runtime_error& e)
        {
            //expected error
            printf(" *<=  Test #%s > OK\n", testNumber.c_str());
            testsResults.emplace_back (" Test #"+testNumber+" "+testName,true);
        }
        catch(const std::exception& e)
        {
            printf(" *<=  Test #%s > Failed\n", testNumber.c_str());
            printf("Error: %s\n",e.what());
            testsResults.emplace_back (" Test #"+testNumber+" "+testName,false);
        }
    }

    printf ("OK\n");

    //Next test
    testNumber = "2.1";
    testName = "Read configuration (key type EC)-> success case";
    printf ("\n----------------------------------------------------------------"
            "-------\n");
    {
        printf (" *=>  Test #%s %s\n", testNumber.c_str (), testName.c_str ());

        try {
            //Do the test here. If error throw expections
            using namespace certgen;

            std::string configFilePath(SELFTEST_DIR_RO + std::string("/test_ec.cfg"));

            std::ifstream configFile(configFilePath);

            std::stringstream configJson;
            configJson << configFile.rdbuf();
            configFile.close();

            cxxtools::SerializationInfo configSi;
            cxxtools::JsonDeserializer deserializer(configJson);
            deserializer.deserialize(configSi);

            CertificateGeneratorConfig conf;

            configSi >>= conf;

            printf (" *<=  Test #%s > OK\n", testNumber.c_str ());
            testsResults.emplace_back (" Test #" + testNumber + " " + testName, true);
        }
        catch (const std::exception &e) {
            printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
            printf ("Error: %s\n", e.what ());
            testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
        }
    }

    printf ("OK\n");
    
    //Next test
    testNumber = "2.2";
    testName = "Read configuration (key type EC)-> error case";
    printf ("\n----------------------------------------------------------------"
            "-------\n");
    {
        printf (" *=>  Test #%s %s\n", testNumber.c_str (), testName.c_str ());

        try {
            //Do the test here. If error throw expections
            using namespace certgen;

            std::string configFilePath(SELFTEST_DIR_RO + std::string("/test_ec_err.cfg"));

            std::ifstream configFile(configFilePath);

            std::stringstream configJson;
            configJson << configFile.rdbuf();
            configFile.close();

            cxxtools::SerializationInfo configSi;
            cxxtools::JsonDeserializer deserializer(configJson);
            deserializer.deserialize(configSi);

            CertificateGeneratorConfig conf;

            configSi >>= conf;

            printf (" *<=  Test #%s > OK\n", testNumber.c_str ());
            testsResults.emplace_back (" Test #" + testNumber + " " + testName, true);
        }
        catch(const std::runtime_error& e)
        {
            //expected error
            printf(" *<=  Test #%s > OK\n", testNumber.c_str());
            testsResults.emplace_back (" Test #"+testNumber+" "+testName,true);
        }
        catch(const std::exception& e)
        {
            printf(" *<=  Test #%s > Failed\n", testNumber.c_str());
            printf("Error: %s\n",e.what());
            testsResults.emplace_back (" Test #"+testNumber+" "+testName,false);
        }
    }

    printf ("OK\n");

    // collect results

    printf("\n-----------------------------------------------------------------------\n");

	uint32_t testsPassed = 0;
	uint32_t testsFailed = 0;


	printf("\tSummary tests from libcert_csr_x509\n");
	for(const auto & result : testsResults)
	{
		if(result.second)
		{
			printf(ANSI_COLOR_GREEN"\tOK " ANSI_COLOR_RESET "\t%s\n",result.first.c_str());
			testsPassed++;
		}
		else
		{
			printf(ANSI_COLOR_RED"\tNOK" ANSI_COLOR_RESET "\t%s\n",result.first.c_str());
			testsFailed++;
		}
	}

	printf("\n-----------------------------------------------------------------------\n");

	if(testsFailed == 0)
	{
		printf(ANSI_COLOR_GREEN"\n %i tests passed, everything is ok\n" ANSI_COLOR_RESET "\n",testsPassed);
	}
	else
	{
		printf(ANSI_COLOR_RED"\n!!!!!!!! %i/%i tests did not pass !!!!!!!! \n" ANSI_COLOR_RESET "\n",testsFailed,(testsPassed+testsFailed));

		assert(false);
	}

    printf ("OK\n");
}

