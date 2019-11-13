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

#include "fty_certificate_generator_classes.h"

#include "certgen_accessor.h"

#include <fty_common_mlm.h>

//  Structure of our class
namespace certgen
{
    CertGenAccessor::CertGenAccessor(fty::SyncClient & reqClient)
        : m_requestClient (reqClient)
    {}

    void CertGenAccessor::generateSelfCertificateReq(
        const std::string & serviceName
    ) const
    {
        fty::Payload payload = sendCommand(GENERATE_SELFSIGNED_CERTIFICATE, {serviceName});
    }

    fty::CsrX509 CertGenAccessor::generateCsr(const std::string & serviceName) const
    {
        fty::Payload payload = sendCommand(GENERATE_CSR, {serviceName});

        return fty::CsrX509(payload[0]);
    }

    void CertGenAccessor::importCertificate(
        const std::string & serviceName,
        const std::string & cert
    ) const
    {
        fty::Payload payload = sendCommand(IMPORT_CERTIFICATE, {serviceName, cert});
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


std::vector<std::pair<std::string,bool>> certgen_accessor_test(mlm::MlmSyncClient & syncClient)
{
    std::vector<std::pair<std::string,bool>> testsResults;
  
    using namespace certgen;

    std::string testNumber, testName;

    //test 1.X
    {
        //test 1.1 => test retrieve a mapping
        testNumber = "1.1";
        testName = "generateSelfCertificateReq";
        printf("\n-----------------------------------------------------------------------\n");
        {
            printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());
            try
            {
                CertGenAccessor accessor(syncClient);
                accessor.generateSelfCertificateReq("test");
                printf(" *<=  Test #%s > Ok\n", testNumber.c_str());
                testsResults.emplace_back (" Test #"+testNumber+" "+testName,true);
            }
            catch(const std::runtime_error& e)
            {
                printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
                printf ("Error: %s\n", e.what ());
                testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
            }
        }
    } // 1.X
  

  return testsResults;
}