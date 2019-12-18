// TODO update description
/*  ========================================================================
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
    ========================================================================
*/

#ifndef CERTGEN_ACCESSOR_H_INCLUDED
#define CERTGEN_ACCESSOR_H_INCLUDED

#include <vector>
#include <string>

namespace certgen
{
    /**
   * @brief access to certgen agent: 
   * @exception std::runtime_error
   */
    class CertGenAccessor
    {
        /**
         * Class methods
         */
        public:
        explicit CertGenAccessor(fty::SyncClient & reqClient);
        
        ~CertGenAccessor() = default;

        /**
         * @brief gets list of all services
         * 
         * @return std::vector<std::string>
         */
        std::vector<std::string> getAllServices();

        /**
         * @brief send request to generate self certificate
         * @param serviceName name of the service
         */
        void generateSelfCertificateReq(const std::string & serviceName);

        /**
         * @brief generate certificate signing request (CSR)
         * @param serviceName name of the service
         * 
         * @return fty::CsrX509 PEM
         */
        fty::CsrX509 generateCsr(const std::string & serviceName);

        /**
         * @brief import certificate
         * @param serviceName name of the service
         * @param cert PEM certificate
         */
        void importCertificate(
            const std::string & serviceName,
            const std::string & cert
        );

        /**
         * @brief get certificate PEM
         * @param serviceName name of the service
         * 
         * @return fty::CertificateX509 object
         */
        fty::CertificateX509 getCertificate(const std::string & serviceName) const;

        /**
         * @brief get existing certificate signing request (CSR)
         * @param serviceName name of the service
         * 
         * @return fty::CsrX509 object
         */
        fty::CsrX509 getPendingCsr(const std::string & serviceName) const;

        /**
         * @brief get existing certificate signing request (CSR) creation date
         * @param serviceName name of the service
         * 
         * @return uint64_t UNIX timestamp
         */
        uint64_t getPendingCsrCreationDate(const std::string & serviceName) const;

        /**
         * @brief remove pending certificate signing request (CSR) for specified service
         * @param serviceName name of the service
         * 
         * @return fty::CsrX509 object
         */
        void removePendingCsr(const std::string & serviceName);


        private:
        /**
         * @brief helper function to send a command
         *
         * @param command command to send
         * @param data array of strings containing data
         */
        fty::Payload sendCommand
        (
            const std::string & command,
            const fty::Payload & data
        ) const;

        /**
         * Class attributes
         */
        private:
        fty::SyncClient & m_requestClient;
    };
} // namescpace certgen

std::vector<std::pair<std::string,bool>> certgen_accessor_test(mlm::MlmSyncClient & syncClient);

#endif
