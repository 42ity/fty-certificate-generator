/*  =========================================================================
    certgen_key_config - class description

    Copyright (C) 2014 - 2019 Eaton

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
    certgen_key_config -
@discuss
@end
*/

#include "certgen_key_config.h"

#include <functional>

//  Structure of our class
namespace certgen
{
    // Static functions map
    std::map<std::string, std::function< KeyConfigParamsPtr() >> factoryFunctions =
    {
        { "RSA", []() { return KeyConfigParamsPtr(new KeyConfigRsaParams()); }},
        { "EC",  []() { return KeyConfigParamsPtr(new KeyConfigECParams()); }}
    };

    // KeyConfig
    void KeyConfig::load(const cxxtools::SerializationInfo& si)
    {
        si.getMember("key_type") >>= m_keyType;

        m_params = KeyConfigParams::create(m_keyType);
        
        si.getMember("key_params") >>= *(m_params);
    }

    void operator>>= (const cxxtools::SerializationInfo& si, KeyConfig & config)
    {
        config.load(si);
    }

    std::ostream& operator<<(std::ostream& os, const KeyConfig & k)
    {
        os << "Key type: " << k.keyType() << std::endl;
        os << "Key params: " << std::endl << k.params()->toString();

        return os;
    }

// StorageConfigParams
    KeyConfigParamsPtr KeyConfigParams::create(const std::string & keyType)
    {
        return (factoryFunctions.at(keyType))();
    }

    void operator>>= (const cxxtools::SerializationInfo& si, KeyConfigParams & configParams)
    {
        configParams.load(si);
    }

    void KeyConfigRsaParams::load(const cxxtools::SerializationInfo& si)
    {
        si.getMember("rsa_length") >>= m_rsaLength;
    }

    std::string KeyConfigRsaParams::toString() const
    {
        std::string outString("\tRSA length: ");
        outString += std::to_string(m_rsaLength);
        outString += "\n";

        return outString;
    }


    void KeyConfigECParams::load(const cxxtools::SerializationInfo& si)
    {
        si.getMember("ec_curve_type") >>= m_ecCurveType;
    }

    std::string KeyConfigECParams::toString() const
    {
        std::string outString("\tEC curve type: ");
        outString += (m_ecCurveType);
        outString += "\n";

        return outString;
    }

} // namescpace certgen


//  --------------------------------------------------------------------------
//  Self test of this class

// If your selftest reads SCMed fixture data, please keep it in
// src/selftest-ro; if your test creates filesystem objects, please
// do so under src/selftest-rw.
// The following pattern is suggested for C selftest code:
//    char *filename = NULL;
//    filename = zsys_sprintf ("%s/%s", SELFTEST_DIR_RO, "mytemplate.file");
//    assert (filename);
//    ... use the "filename" for I/O ...
//    zstr_free (&filename);
// This way the same "filename" variable can be reused for many subtests.
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

void certgen_key_config_test (bool verbose)
{

    //  @selftest
    //  Simple create/destroy test
    //  @end

    printf (" * certgen_key_config: ");

    std::vector<std::pair<std::string, bool>> testsResults;

    std::string testNumber;
    std::string testName;

    //Next test
    testNumber = "1.1";
    testName = "Read RSA key configuration-> success case";
    printf ("\n----------------------------------------------------------------"
            "-------\n");
    {
        printf (" *=>  Test #%s %s\n", testNumber.c_str (), testName.c_str ());

        try {
            //Do the test here. If error throw expections
            using namespace certgen;

            std::string configFilePath(SELFTEST_DIR_RO + std::string("/certgen_key_rsa.cfg"));

            std::ifstream configFile(configFilePath);

            std::stringstream configJson;
            configJson << configFile.rdbuf();
            configFile.close();

            cxxtools::SerializationInfo configSi;
            cxxtools::JsonDeserializer deserializer(configJson);
            deserializer.deserialize(configSi);

            KeyConfig keyConf;

            configSi >>= keyConf;

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
    testName = "Read RSA key configuration-> error case";
    printf ("\n----------------------------------------------------------------"
            "-------\n");
    {
        printf (" *=>  Test #%s %s\n", testNumber.c_str (), testName.c_str ());

        try {
            //Do the test here. If error throw expections
            using namespace certgen;

            std::string configFilePath(SELFTEST_DIR_RO + std::string("/certgen_key_rsa_err.cfg"));

            std::ifstream configFile(configFilePath);

            std::stringstream configJson;
            configJson << configFile.rdbuf();
            configFile.close();

            cxxtools::SerializationInfo configSi;
            cxxtools::JsonDeserializer deserializer(configJson);
            deserializer.deserialize(configSi);

            KeyConfig keyConf;

            configSi >>= keyConf;

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
    testName = "Read EC key configuration-> success case";
    printf ("\n----------------------------------------------------------------"
            "-------\n");
    {
        printf (" *=>  Test #%s %s\n", testNumber.c_str (), testName.c_str ());

        try {
            //Do the test here. If error throw expections
            using namespace certgen;

            std::string configFilePath(SELFTEST_DIR_RO + std::string("/certgen_key_ec.cfg"));

            std::ifstream configFile(configFilePath);

            std::stringstream configJson;
            configJson << configFile.rdbuf();
            configFile.close();

            cxxtools::SerializationInfo configSi;
            cxxtools::JsonDeserializer deserializer(configJson);
            deserializer.deserialize(configSi);

            KeyConfig keyConf;

            configSi >>= keyConf;

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
    testName = "Read EC key configuration-> error case";
    printf ("\n----------------------------------------------------------------"
            "-------\n");
    {
        printf (" *=>  Test #%s %s\n", testNumber.c_str (), testName.c_str ());

        try {
            //Do the test here. If error throw expections
            using namespace certgen;

            std::string configFilePath(SELFTEST_DIR_RO + std::string("/certgen_key_ec_err.cfg"));

            std::ifstream configFile(configFilePath);

            std::stringstream configJson;
            configJson << configFile.rdbuf();
            configFile.close();

            cxxtools::SerializationInfo configSi;
            cxxtools::JsonDeserializer deserializer(configJson);
            deserializer.deserialize(configSi);

            KeyConfig keyConf;

            configSi >>= keyConf;

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
