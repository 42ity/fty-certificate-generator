/*  =========================================================================
    certgen_storage_config - class description

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
    certgen_storage_config -
@discuss
@end
*/

#include "certgen_storage_config.h"

//  Structure of our class
namespace certgen
{
// StorageConfig
    void StorageConfig::load(const cxxtools::SerializationInfo& si)
    {
        si.getMember("storage_type") >>= m_storageType;
        si.getMember("permanent") >>= m_permanent;

        m_params = StorageConfigParams::create(m_storageType);
        
        si.getMember("storage_params") >>= *(m_params);
    }

    void operator>>= (const cxxtools::SerializationInfo& si, StorageConfig & config)
    {
        config.load(si);
    }

    std::ostream& operator<<(std::ostream& os, const StorageConfig & s)
    {
        os << "Storage type: " << s.storageType() << std::endl;
        os << "Permanent: " << s.isPermanent() << std::endl;
        os << "Storage params: " << std::endl << s.params()->toString();

        return os;
    }

// StorageConfigParams
    StorageConfigParamsPtr StorageConfigParams::create(const std::string & storageType)
    {
        if(storageType == "secw")
        {
            return StorageConfigParamsPtr(new StorageConfigSecwParams());
        }
        if(storageType == "file")
        {
            return StorageConfigParamsPtr(new StorageConfigFileParams());
        }
        else
        {
            throw std::runtime_error( "Storage type <"+storageType+"> is not supported");
        }
    }

    void operator>>= (const cxxtools::SerializationInfo& si, StorageConfigParams & configParams)
    {
        configParams.load(si);
    }

    void StorageConfigSecwParams::load(const cxxtools::SerializationInfo& si)
    {
        si.getMember("secw_portfolio") >>= m_portfolio;
        si.getMember("secw_document_name") >>= m_documentName;
        si.getMember("secw_document_usages") >>= m_documentUsages;

        // helper data for counter-agent connection, not part of cert data
        if (si.findMember("secw_socket_path")) {
            si.getMember("secw_socket_path") >>= m_secwSocketPath;
        }
    }

    std::string StorageConfigSecwParams::toString() const
    {
        std::string outString("\tPortfolio: ");
        outString += m_portfolio;
        outString += "\n";

        outString += "\tDocument name: ";
        outString += m_documentName;
        outString += "\n";

        outString += "\tDocument usages: ";
        for (const std::string & docUsage : m_documentUsages)
        {
            outString += "\t\t";
            outString += docUsage;
            outString += "\n";
        }

        return outString;
    }

    void StorageConfigFileParams::load(const cxxtools::SerializationInfo& si)
    {
        si.getMember("file_cert_path")   >>= m_fileCertificatePath;
        si.getMember("file_cert_format") >>= m_fileCertificateFormat;
        si.getMember("file_key_path")    >>= m_fileKeyPath;
        si.getMember("file_key_format")  >>= m_fileKeyFormat;
    }

    std::string StorageConfigFileParams::toString() const
    {
        std::string outString("Certificate");
        outString += "\n";
        outString += "\t- File path";
        outString += m_fileCertificatePath;
        outString += "\t- File format";
        outString += m_fileCertificateFormat;
        outString += "\n";
        
        outString += "Key\n";
        outString += "\t- File path";
        outString += m_fileKeyPath;
        outString += "\t- File format";
        outString += m_fileKeyFormat;
        
        return outString;
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
#define SELFTEST_DIR_RO "src/selftest-ro"
#define SELFTEST_DIR_RW "src/selftest-rw"

void certgen_storage_config_test (bool verbose)
{
    printf (" * certgen_storage_config: ");

    //  @selftest
    //  Simple create/destroy test
    //  @end
    std::vector<std::pair<std::string, bool>> testsResults;

    std::string testNumber;
    std::string testName;

    //Next test
    testNumber = "1.1";
    testName = "Read secw storage configuration";
    printf ("\n----------------------------------------------------------------"
            "-------\n");
    {
        printf (" *=>  Test #%s %s\n", testNumber.c_str (), testName.c_str ());

        try {
            //Do the test here. If error throw expections
            using namespace certgen;

            std::string configFilePath(SELFTEST_DIR_RO + std::string("/certgen_storage_secw.cfg"));

            std::ifstream configFile(configFilePath);

            std::stringstream configJson;
            configJson << configFile.rdbuf();
            configFile.close();

            cxxtools::SerializationInfo configSi;
            cxxtools::JsonDeserializer deserializer(configJson);
            deserializer.deserialize(configSi);

            StorageConfig storageConf;

            configSi >>= storageConf;

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
    testName = "Read file storage configuration";
    printf ("\n----------------------------------------------------------------"
            "-------\n");
    {
        printf (" *=>  Test #%s %s\n", testNumber.c_str (), testName.c_str ());

        try {
            //Do the test here. If error throw expections
            using namespace certgen;

            std::string configFilePath(SELFTEST_DIR_RO + std::string("/certgen_storage_file.cfg"));

            std::ifstream configFile(configFilePath);

            std::stringstream configJson;
            configJson << configFile.rdbuf();
            configFile.close();

            cxxtools::SerializationInfo configSi;
            cxxtools::JsonDeserializer deserializer(configJson);
            deserializer.deserialize(configSi);

            StorageConfig storageConf;

            configSi >>= storageConf;

            printf (" *<=  Test #%s > OK\n", testNumber.c_str ());
            testsResults.emplace_back (" Test #" + testNumber + " " + testName, true);
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
    testNumber = "1.3";
    testName = "Read storage configuration-> error case";
    printf ("\n----------------------------------------------------------------"
            "-------\n");
    {
        printf (" *=>  Test #%s %s\n", testNumber.c_str (), testName.c_str ());

        try {
            //Do the test here. If error throw expections
            using namespace certgen;

            std::string configFilePath(SELFTEST_DIR_RO + std::string("/certgen_storage_err.cfg"));

            std::ifstream configFile(configFilePath);

            std::stringstream configJson;
            configJson << configFile.rdbuf();
            configFile.close();

            cxxtools::SerializationInfo configSi;
            cxxtools::JsonDeserializer deserializer(configJson);
            deserializer.deserialize(configSi);

            StorageConfig storageConf;

            configSi >>= storageConf;

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