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
        fty::Payload payload;
        try
        {
            payload = sendCommand(GENERATE_SELFSIGNED_CERTIFICATE, {serviceName});
        }
        catch (const std::exception& e)
        {
            log_info("certificate generator accessor returned '%s'", e.what());
        }
    }

    std::string CertGenAccessor::generateCsr(const std::string & serviceName) const
    {
        fty::Payload payload;
        try
        {
            payload = sendCommand(GENERATE_CSR, {serviceName});
        }
        catch (const std::exception& e)
        {
            log_info("certificate generator accessor returned '%s'", e.what());
        }

        return payload[0];
    }

    void CertGenAccessor::importCertificate(
        const std::string & serviceName,
        const std::string & cert
    ) const
    {
        fty::Payload payload;
        try
        {
            payload = sendCommand(IMPORT_CERTIFICATE, {serviceName, cert});
        }
        catch (const std::exception& e)
        {
            log_info("certificate generator accessor returned '%s'", e.what());
        }
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
                throw std::runtime_error("Missing data for error");
            }
        }

        return recMessage;    
    }
} // namescpace certgen


//  Self test of this class

#define SELFTEST_DIR_RO "src/selftest-ro"
#define SELFTEST_DIR_RW "src/selftest-rw"

void certgen_accessor_test (bool verbose)
{
    printf (" * certgen_accessor: ");

    printf ("OK\n");
}
