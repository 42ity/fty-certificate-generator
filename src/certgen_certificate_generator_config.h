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

#ifndef CERTGEN_CERTIFICATE_GENERATOR_CONFIG_H_INCLUDED
#define CERTGEN_CERTIFICATE_GENERATOR_CONFIG_H_INCLUDED

#include <string>
#include <vector>
#include <memory>
#include <ostream>

#include "certgen_key_config.h"
#include "certgen_certificate_config.h"
#include "certgen_storage_config.h"
#include "certgen_certificate_generator_config.h"

#include "cxxtools/serializationinfo.h"
#include "cxxtools/jsondeserializer.h"

namespace certgen
{
    class CertificateGeneratorConfig
    {
    public:
        CertificateGeneratorConfig() = default;

        const std::string       & version() const { return m_version; };
        const KeyConfig         & keyConf() const { return m_keyConf; };
        const CertificateConfig & certConf() const { return m_certConf; };
        const StorageConfig     & storageConf() const { return m_storageConf; };

        void load(const cxxtools::SerializationInfo& si);

    private:
        std::string         m_version;
        KeyConfig           m_keyConf;
        CertificateConfig   m_certConf;
        StorageConfig       m_storageConf;
        
    };

    void operator>>= (const cxxtools::SerializationInfo& si, CertificateGeneratorConfig & config);
    std::ostream& operator<<(std::ostream& os, const CertificateGeneratorConfig & c);

} // namescpace certgen

void certgen_certificate_generator_config_test (bool verbose);

#endif
