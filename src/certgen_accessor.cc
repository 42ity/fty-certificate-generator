/*  =========================================================================
    certgen_accessor - accessor to interface with certgen library

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

#include <string>

#include <fty_common_mlm.h>

#include "fty_certificate_generator_classes.h"
#include "certgen_accessor.h"

//  Structure of our class
namespace certgen
{
    CertGenAccessor::CertGenAccessor(fty::SyncClient & reqClient)
        : m_requestClient (reqClient)
    {}

    std::vector<std::string> CertGenAccessor::getAllServices()
    {
        fty::Payload payload = sendCommand(GET_SERVICES_LIST, {});

        return payload;
    }

    void CertGenAccessor::generateSelfCertificateReq(
        const std::string & serviceName
    )
    {
        fty::Payload payload = sendCommand(GENERATE_SELFSIGNED_CERTIFICATE, {serviceName});
    }

    fty::CsrX509 CertGenAccessor::generateCsr(const std::string & serviceName)
    {
        fty::Payload payload = sendCommand(GENERATE_CSR, {serviceName});

        return fty::CsrX509(payload.at(0));
    }

    void CertGenAccessor::importCertificate(
        const std::string & serviceName,
        const std::string & cert
    )
    {
        fty::Payload payload = sendCommand(IMPORT_CERTIFICATE, {serviceName, cert});
    }

    
    fty::CertificateX509 CertGenAccessor::getCertificate(const std::string & serviceName) const
    {
        fty::Payload payload = sendCommand(GET_CERTIFICATE, {serviceName});

        return fty::CertificateX509(payload.at(0));
    }

    fty::CsrX509 CertGenAccessor::getPendingCsr(const std::string & serviceName) const
    {
        fty::Payload payload = sendCommand(GET_PENDING_CSR, {serviceName});

        return fty::CsrX509(payload.at(0));
    }

    uint64_t CertGenAccessor::getPendingCsrCreationDate(const std::string & serviceName) const
    {
        fty::Payload payload = sendCommand(GET_PENDING_CSR_CREAT_DATE, {serviceName});

        return static_cast<uint64_t>(std::stoi(payload.at(0)));
    }

    void CertGenAccessor::removePendingCsr(const std::string & serviceName)
    {
        fty::Payload payload = sendCommand(REMOVE_PENDING_CSR, {serviceName});
    }

    // send helper function
    fty::Payload CertGenAccessor::sendCommand(
        const std::string & command,
        const fty::Payload & data
    ) const
    {
        fty::Payload payload = {command};

        std::copy(data.begin(), data.end(), back_inserter(payload));

        fty::Payload recMessage = m_requestClient.syncRequestWithReply(payload);

        if(recMessage[0] == "ERROR")
        {
            // error - throw exception
            if(recMessage.size() == 2)
            {
                throw std::runtime_error(recMessage.at(1));
            }
            else
            {
                throw std::runtime_error("Unknown error");
            }
        }

        return recMessage;    
    }
} // namescpace certgen

//  --------------------------------------------------------------------------
//  Test of this class => This is used by certgen_certificate_generator_server_test
//  --------------------------------------------------------------------------
#include <time.h>
#include <set>

std::vector<std::pair<std::string,bool>> certgen_accessor_test(mlm::MlmSyncClient & syncClient)
{
    std::vector<std::pair<std::string,bool>> testsResults;
  
    using namespace certgen;

    std::string testNumber, testName;

    //test 1.X
    {
        //test 1.1
        testNumber = "1.1";
        testName = "generateSelfCertificateReq => valid configuration file";
        printf("\n-----------------------------------------------------------------------\n");
        {
            printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());
            try
            {
                CertGenAccessor accessor(syncClient);
                accessor.generateSelfCertificateReq("service-1");
                printf(" *<=  Test #%s > Ok\n", testNumber.c_str());
                testsResults.emplace_back (" Test #"+testNumber+" "+testName,true);
            }
            catch(const std::exception& e)
            {
                printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
                printf ("Error: %s\n", e.what ());
                testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
            }
        }
        
        //test 1.2
        testNumber = "1.2";
        testName = "generateSelfCertificateReq => invalid configuration file";
        printf("\n-----------------------------------------------------------------------\n");
        {
            printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());
            try
            {
                CertGenAccessor accessor(syncClient);
                accessor.generateSelfCertificateReq("fail");
                throw std::invalid_argument("Found configuration file");
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
    } // 1.X
    
    //test 2.X
    {
        //test 2.1
        testNumber = "2.1";
        testName = "generateCsr => success case";
        printf("\n-----------------------------------------------------------------------\n");
        {
            printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());
            try
            {
                CertGenAccessor accessor(syncClient);
                fty::CsrX509 csr = accessor.generateCsr("service-1");
                printf(" *<=  Test #%s > Ok\n", testNumber.c_str());
                testsResults.emplace_back (" Test #"+testNumber+" "+testName,true);
            }
            catch(const std::exception& e)
            {
                printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
                printf ("Error: %s\n", e.what ());
                testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
            }
        }
        
        //test 2.2
        testNumber = "2.2";
        testName = "generateCsr => create two requests for the same service";
        printf("\n-----------------------------------------------------------------------\n");
        {
            printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());
            try
            {
                CertGenAccessor accessor(syncClient);
                fty::CsrX509 csr = accessor.generateCsr("service-1");

                fty::CsrX509 newCsr = accessor.generateCsr("service-1");
                if(newCsr.getPublicKey().getPem() == csr.getPublicKey().getPem())
                {
                    printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
                    printf ("Error: %s\n", "Both requests have the same publicKey");
                    testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
                }
                else
                {
                    printf(" *<=  Test #%s > Ok\n", testNumber.c_str());
                    testsResults.emplace_back (" Test #"+testNumber+" "+testName,true);
                }
            }
            catch(const std::exception& e)
            {
                printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
                printf ("Error: %s\n", e.what ());
                testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
            }
        }
        
        //test 2.3
        testNumber = "2.3";
        testName = "generateCsr => create two requests for two different services";
        printf("\n-----------------------------------------------------------------------\n");
        {
            printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());
            try
            {
                CertGenAccessor accessor(syncClient);
                fty::CsrX509 csr1 = accessor.generateCsr("service-1");

                fty::CsrX509 csr2 = accessor.generateCsr("service-2");

                if(csr1.getPublicKey().getPem() == csr2.getPublicKey().getPem())
                {
                    printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
                    printf ("Error: %s\n", "Both requests have the same publicKey");
                    testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
                }
                else
                {
                    printf(" *<=  Test #%s > Ok\n", testNumber.c_str());
                    testsResults.emplace_back (" Test #"+testNumber+" "+testName,true);
                }
            }
            catch(const std::exception& e)
            {
                printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
                printf ("Error: %s\n", e.what ());
                testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
            }
        }
    
    } // 2.X
    
    //test 3.X
    {
        //test 3.1
        testNumber = "3.1";
        testName = "getPendingCsr => get existing pending CSR";
        printf("\n-----------------------------------------------------------------------\n");
        {
            printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());
            try
            {
                CertGenAccessor accessor(syncClient);
                fty::CsrX509 csr = accessor.generateCsr("service-1");

                fty::CsrX509 csrRet = accessor.getPendingCsr("service-1");

                if(csr.getPublicKey().getPem() != csrRet.getPublicKey().getPem())
                {
                    printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
                    printf ("Error: %s\n", "PEM does not match");
                    testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
                }
                else
                {
                    printf(" *<=  Test #%s > Ok\n", testNumber.c_str());
                    testsResults.emplace_back (" Test #"+testNumber+" "+testName,true);
                }
            }
            catch(const std::exception& e)
            {
                printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
                printf ("Error: %s\n", e.what ());
                testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
            }
        }

        //test 3.2
        testNumber = "3.2";
        testName = "getPendingCsr => try to get pending CSR which does not exist";
        printf("\n-----------------------------------------------------------------------\n");
        {
            printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());
            try
            {
                CertGenAccessor accessor(syncClient);

                accessor.removePendingCsr("service-1");

                fty::CsrX509 csrRet = accessor.getPendingCsr("service-1");

                throw std::invalid_argument("CSR has been found");
            }
            catch(const std::runtime_error& e)
            {
                printf(" *<=  Test #%s > Ok\n", testNumber.c_str());
                testsResults.emplace_back (" Test #"+testNumber+" "+testName, true);
            }
            catch(const std::exception& e)
            {
                printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
                printf ("Error: %s\n", e.what ());
                testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
            }
        }

        //test 3.3
        testNumber = "3.3";
        testName = "getPendingCsr => get pending CSR for two different services";
        printf("\n-----------------------------------------------------------------------\n");
        {
            printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());
            try
            {
                CertGenAccessor accessor(syncClient);
                fty::CsrX509 csr1 = accessor.generateCsr("service-1");
                fty::CsrX509 csr2 = accessor.generateCsr("service-2");

                fty::CsrX509 csrRet1 = accessor.getPendingCsr("service-1");
                fty::CsrX509 csrRet2 = accessor.getPendingCsr("service-2");

                if((csr1.getPublicKey().getPem() != csrRet1.getPublicKey().getPem()) || (csr2.getPublicKey().getPem() != csrRet2.getPublicKey().getPem()))
                {
                    printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
                    printf ("Error: %s\n", "CSR PEM does not match the one requested");
                    testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
                }
                else
                {
                    printf(" *<=  Test #%s > Ok\n", testNumber.c_str());
                    testsResults.emplace_back (" Test #"+testNumber+" "+testName,true);
                }
            }
            catch(const std::exception& e)
            {
                printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
                printf ("Error: %s\n", e.what ());
                testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
            }
        }

        //test 3.4
        testNumber = "3.4";
        testName = "getPendingCsr => get pending CSR creation date (SUCCESS CASE)";
        printf("\n-----------------------------------------------------------------------\n");
        {
            printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());
            try
            {
                CertGenAccessor accessor(syncClient);
            
                time_t beforeTimestamp = time(NULL);
                fty::CsrX509 csr1 = accessor.generateCsr("service-1");
                time_t afterTimestamp = time(NULL);

                uint64_t csrTimestamp = accessor.getPendingCsrCreationDate("service-1");

                // CSR generation should take less than one second, but it is safer to check against a timestamp range
                if(static_cast<uint64_t>(beforeTimestamp) > csrTimestamp || static_cast<uint64_t>(afterTimestamp) < csrTimestamp)
                {
                    printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
                    printf ("Error: %s\n", "CSR timestamp does not match creation date");
                    testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
                }
                else
                {
                    printf(" *<=  Test #%s > Ok\n", testNumber.c_str());
                    testsResults.emplace_back (" Test #"+testNumber+" "+testName,true);
                }
            }
            catch(const std::exception& e)
            {
                printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
                printf ("Error: %s\n", e.what ());
                testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
            }
        }

        //test 3.5
        testNumber = "3.5";
        testName = "getPendingCsr => get pending CSR creation date (ERROR CASE)";
        printf("\n-----------------------------------------------------------------------\n");
        {
            printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());
            try
            {
                CertGenAccessor accessor(syncClient);
                
                accessor.removePendingCsr("service-1");

                uint64_t csrTimestamp = accessor.getPendingCsrCreationDate("Service-1");
                
                throw std::invalid_argument("Got timestamp for non existing pending CSR");

                std::cout << csrTimestamp << std::endl; // necessary to avoid compilation error (unused variable csrTimestamp)
            }
            catch(const std::runtime_error& e)
            {
                //expected error
                printf(" *<=  Test #%s > OK\n", testNumber.c_str());
                testsResults.emplace_back (" Test #"+testNumber+" "+testName,true);
            }
            catch(const std::exception& e)
            {
                printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
                printf ("Error: %s\n", e.what ());
                testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
            }
        }
    } // 3.X

    //test 4.X
    {
        //test 4.1
        testNumber = "4.1";
        testName = "getCertificate => success case";
        printf("\n-----------------------------------------------------------------------\n");
        {
            printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());
            try
            {
                CertGenAccessor accessor(syncClient);
                fty::CertificateX509 cert(accessor.getCertificate("service-1"));

                printf(" *<=  Test #%s > Ok\n", testNumber.c_str());
                testsResults.emplace_back (" Test #"+testNumber+" "+testName,true);
            }
            catch(const std::exception& e)
            {
                printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
                printf ("Error: %s\n", e.what ());
                testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
            }
        } 
        //test 4.2
        testNumber = "4.2";
        testName = "getCertificate => invalid configuration file";
        printf("\n-----------------------------------------------------------------------\n");
        {
            printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());
            try
            {
                CertGenAccessor accessor(syncClient);
                fty::CertificateX509 cert(accessor.getCertificate("fail"));

                throw std::invalid_argument("Found configuration file");
            }
            catch(const std::runtime_error& e)
            {
                //expected error
                printf(" *<=  Test #%s > OK\n", testNumber.c_str());
                testsResults.emplace_back (" Test #"+testNumber+" "+testName,true);
            }
            catch(const std::exception& e)
            {
                printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
                printf ("Error: %s\n", e.what ());
                testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
            }
        } 
    } // 4.X
    
    //test 5.X
    {
        //test 5.1
        testNumber = "5.1";
        testName = "getAllServices";
        printf("\n-----------------------------------------------------------------------\n");
        {
            printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());
            try
            {
                CertGenAccessor accessor(syncClient);
                std::vector<std::string> retList = accessor.getAllServices();

                std::set<std::string> serviceSet;
                serviceSet.insert(std::string("service-2"));
                serviceSet.insert(std::string("service-1"));

                std::set<std::string> retSet;
                for(const std::string & service : retList)
                {
                    retSet.insert(service);
                }

                if(retSet != serviceSet)
                {
                    throw std::invalid_argument("Expected and received service lists do not match");
                }

                printf(" *<=  Test #%s > Ok\n", testNumber.c_str());
                testsResults.emplace_back (" Test #"+testNumber+" "+testName,true);
            }
            catch(const std::exception& e)
            {
                printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
                printf ("Error: %s\n", e.what ());
                testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
            }
        }
    } // 5.X
    
    //test 6.X
    /*
    {
        //test 6.1
        testNumber = "6.1";
        testName = "importCertificate => valid configuration file";
        printf("\n-----------------------------------------------------------------------\n");
        {
            printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());
            try
            {
                CertGenAccessor accessor(syncClient);
                fty::CsrX509 csr = accessor.generateCsr("service-1");

                fty::Keys keyPair(csr.getPublicKey().getPem());

                fty::CertificateConfig config;

                // TODO missing implementation in CertificateX509

                fty::CertificateX509 cert = fty::CertificateX509::signCsr(keyPair, config);

                accessor.importCertificate("service-1", cert.getPem());


                printf(" *<=  Test #%s > Ok\n", testNumber.c_str());
                testsResults.emplace_back (" Test #"+testNumber+" "+testName,true);
            }
            catch(const std::exception& e)
            {
                printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
                printf ("Error: %s\n", e.what ());
                testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
            }
        }
    } // 6.X
    */
  

  return testsResults;
}