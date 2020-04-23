/*  =========================================================================
    certgen_certificate_config - class description

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
    certgen_certificate_config -
@discuss
@end
*/

#include "fty_certificate_generator_classes.h"

//  Structure of our class
namespace certgen
{
    void CertificateConfig::deserialize (const cxxtools::SerializationInfo & si)
    {
        si.getMember("signature_type") >>= m_signatureType;

        si.getMember("validity") >>= m_validity;

        si.getMember("validity_offset") >>= m_validityOffset;

        si.getMember("certificate_level") >>= m_certificateLevel;
    }

    void operator>>= (const cxxtools::SerializationInfo &si, CertificateConfig & config)
    {
        config.deserialize (si);
    }
} // namescpace certgen



//  --------------------------------------------------------------------------
//  Self test of this class
#define SELFTEST_DIR_RO "src/selftest-ro"
#define SELFTEST_DIR_RW "src/selftest-rw"

void
certgen_certificate_config_test (bool verbose)
{
    printf (" * certgen_certificate_config: ");

    //  @selftest
    //  Simple deserialize test
    {
    std::string configFilePath (SELFTEST_DIR_RO + std::string ("/certificate.config"));
    std::ifstream configFile (configFilePath);

    if (configFile)
    {
        std::stringstream configJson;
        configJson << configFile.rdbuf();
        configFile.close ();

        cxxtools::SerializationInfo configSi;
        cxxtools::JsonDeserializer deserializer (configJson);
        deserializer.deserialize (configSi);

        certgen::CertificateConfig config;
        configSi >>= config;

        assert (config.getSignatureType() == "SHA256");
        assert (config.getValidity() == 730);
    }
    }

    {
    std::string configFilePath (SELFTEST_DIR_RO + std::string ("/certificate.config.bad"));
    std::ifstream configFile (configFilePath);

    if (configFile)
    {
        std::stringstream configJson;
        configJson << configFile.rdbuf();
        configFile.close ();

        try {
            cxxtools::SerializationInfo configSi;
            cxxtools::JsonDeserializer deserializer (configJson);
            deserializer.deserialize (configSi);

            certgen::CertificateConfig config;
            configSi >>= config;

            assert (config.getSignatureType() == "SHA256");
            assert (config.getValidity() == 730);
        }
        catch (cxxtools::SerializationMemberNotFound &e)
        {
            assert (streq (e.what(), "Missing info for 'validity'"));
        }
    }
    }
    //  @end
    printf ("OK\n");


}
