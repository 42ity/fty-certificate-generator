/*  =========================================================================
    certgen_certificate_generator_server - class description

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
    certgen_certificate_generator_server -
@discuss
@end
*/

#include "fty_certificate_generator_classes.h"
#include <chrono>
#include <netdb.h>

// because there is NO std::chrono::days in C++14
#define HOURS_IN_DAY        24

#define ORGANIZATION_UNIT   "Power quality"
#define ORGANIZATION        "Eaton"
#define LOCALITY            "Grenoble"
#define STATE               "38"
#define COUNTRY             "FR"
#define EMAIL               "noemail"

//  Structure of our class

namespace certgen
{
    using namespace fty;
    using namespace std::placeholders;

    CertificateGeneratorServer::CertificateGeneratorServer(const std::string & configPath)
        : m_configPath(configPath)
    {
        //initiate the commands handlers
        m_supportedCommands[GENERATE_SELFSIGNED_CERTIFICATE] = std::bind(&CertificateGeneratorServer::handleGenerateSelfsignedCertificate, this, _1);
        m_supportedCommands[GENERATE_CSR] = std::bind(&CertificateGeneratorServer::handleGenerateCSR, this, _1);
        m_supportedCommands[IMPORT_CERTIFICATE] = std::bind(&CertificateGeneratorServer::handleImportCertificate, this, _1);
        m_supportedCommands[GET_PENDING_CSR] = std::bind(&CertificateGeneratorServer::handleGetPendingCSR, this, _1);
        m_supportedCommands[REMOVE_PENDING_CSR] = std::bind(&CertificateGeneratorServer::handleRemovePendingCSR, this, _1);
    }

    Payload CertificateGeneratorServer::handleRequest(const Sender & /*sender*/, const Payload & payload)
    {
        try
        {
            if (payload.size() == 0)
            {
                throw std::runtime_error("Command frame is empty");
            }

            Command cmd = payload.at(0);
            if (cmd == "ERROR" || cmd == "OK")
            {
                //avoid loop
                return {};
            }

            //check if the command exists in the system
            if (m_supportedCommands.count(cmd) == 0)
            {
                throw std::runtime_error(cmd + "not supported");
            }
            FctCommandHandler cmdHandler = m_supportedCommands[cmd];

            //create copy of the payload
            std::vector<std::string> params(payload.begin() + 1, payload.end());

            std::string result = cmdHandler(params);
            return {result};
        }
        catch (std::exception &e)
        {
            log_error("Unexpected error: %s", e.what());
            return {"ERROR", e.what()};
        }
        catch (...) //show must go one => Log and ignore the unknown error
        {
            log_error("Unexpected error: unknown");
            return {"ERROR", ""};
        }
    }

    static std::string getSystemHostname()
    {
        char name[NI_MAXHOST];
        int rv = gethostname (name, sizeof(name));
        if (rv != 0)
        {
            throw std::runtime_error ("Error while getting hostname");
        }

        return std::string (name);
    }

    static std::list<std::string> getSystemDomainNames()
    {
        /* NOTE: host name resolution looks at first into /etc/hosts,
         * but on our systems, that one contains just hostname without domain.
         * Therefore, we will reuse fty-envvars which reads /etc/resolv.conf
         * and therefore contains the FQDN(s) we want.
         */
        std::list<std::string> result;
        const char *fqdns = ::getenv ("ENV_KNOWNFQDNS");
        if (fqdns == NULL || streq (fqdns, ""))
        {
            log_warning ("no FQDNs found in the system");
            return result;
        }

        std::stringstream fqdnsStr (fqdns);

        std::string name;
        // envvar contains comma-separated list of FQDNs
        while (std::getline (fqdnsStr, name, ','))
        {
            std::cerr << "domain name: " << name << std::endl;
            // skip localhost
            if (name != "localhost")
            {
                result.push_back (name);
            }
        }

        return result;
    }

    static bool isSystemWithoutDHCP ()
    {
        std::ifstream configFile ("/etc/network/interfaces");
        if (!configFile)
        {
            throw std::runtime_error ("Could not open file " + std::string ("/etc/network/interfaces"));
        }

        configFile.exceptions ( std::ifstream::failbit | std::ifstream::badbit );
        std::stringstream configInterfaces;
        configInterfaces << configFile.rdbuf();
        configFile.close ();

        auto found = configInterfaces.str().find("dhcp");
        return (found == std::string::npos);
    }

    static std::list<std::string> getSystemIPs()
    {
        struct ifaddrs *interfaces, *iface;
        char host[NI_MAXHOST];
        std::list<std::string> result;

        if (getifaddrs (&interfaces) == -1)
        {
            throw std::runtime_error ("Unable to get IP adresses");
        }
        iface = interfaces;
        for (iface = interfaces; iface != NULL; iface = iface->ifa_next)
        {
            if (iface->ifa_addr == NULL) continue;
            int family = iface->ifa_addr->sa_family;
            if ( getnameinfo(iface->ifa_addr,
                    (family == AF_INET) ? sizeof(struct sockaddr_in) :
                    sizeof(struct sockaddr_in6),
                    host, NI_MAXHOST,
                    NULL, 0, NI_NUMERICHOST) == 0
               )
            {
                // sometimes IPv6 addres looks like ::2342%IfaceName
                char *p = strchr (host, '%');
                if (p) *p = 0;

                // skip loopback
                if (streq (host, "127.0.0.1") || streq (host, "::1"))
                {
                    continue;
                }

                log_error ("ip = %s", host);
                auto it = std::find (result.begin(), result.end(), host);
                if (it == result.end())
                {
                    result.push_back (host);
                }
            }
        }
        freeifaddrs (interfaces);
        return result;
    }

    static fty::CertificateConfig loadConfig (const std::string & configVersion, const certgen::CertificateConfig & conf)
    {

        fty::CertificateConfig config;
        // fill the configuration data
        uint8_t version;
        std::istringstream versionStr (configVersion);
        versionStr >> version;
        config.setVersion(version);

        std::chrono::hours validityOffset (HOURS_IN_DAY * conf.getValidityOffset());
        std::chrono::time_point<std::chrono::system_clock, std::chrono::seconds> currentTimestamp =
            std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());
        std::chrono::time_point<std::chrono::system_clock, std::chrono::seconds> startTimestamp = currentTimestamp + validityOffset;
        config.setValidFrom(startTimestamp.time_since_epoch().count());

        std::chrono::hours validity (HOURS_IN_DAY * conf.getValidity());
        currentTimestamp = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());
        std::chrono::time_point<std::chrono::system_clock, std::chrono::seconds> endTimestamp = currentTimestamp + validity;
        config.setValidTo(endTimestamp.time_since_epoch().count());

        config.setCountry(COUNTRY);
        config.setState(STATE);
        config.setLocality(LOCALITY);
        config.setOrganization(ORGANIZATION);
        config.setOrganizationUnit(ORGANIZATION_UNIT);
        //NOTE: this field can't be empty and should be used only if we don't have DNS names, so put hostname here
        config.setCommonName(getSystemHostname());
        config.setEmail(EMAIL);

        std::list<std::string> dnsNames = getSystemDomainNames();

        if (isSystemWithoutDHCP())
        {
            config.setIpList(getSystemIPs());
        }
        else if (dnsNames.empty())
        {
            throw std::runtime_error ("No IPs or FQDNs available for configuration of certificate generation");
        }

        config.setDnsList(dnsNames);

        return config;
    }

    // read config helper function
    static CertificateGeneratorConfig getConfig(const std::string & configPath, const std::string & serviceName)
    {
        std::string configFilePath(configPath + serviceName + ".cfg");
        std::ifstream configFile (configFilePath);
        if (!configFile)
        {
            throw std::runtime_error ("Could not open file " + configFilePath);
        }

        configFile.exceptions ( std::ifstream::failbit | std::ifstream::badbit );
        std::stringstream configJson;
        configJson << configFile.rdbuf();
        configFile.close ();

        cxxtools::SerializationInfo certgenSi;
        cxxtools::JsonDeserializer deserializer (configJson);
        deserializer.deserialize (certgenSi);

        CertificateGeneratorConfig certgenConfig;
        certgenSi >>= certgenConfig;

        return certgenConfig;
    }

    static Keys generateKeys (const KeyConfig & conf)
    {
        std::string keyType = conf.keyType();
        if (keyType == "RSA")
        {
            KeyConfigRsaParams *rsaParams = dynamic_cast<KeyConfigRsaParams *>(conf.params().get());
            return Keys::generateRSA(rsaParams->rsaLength());
        }
        else if (keyType == "EC")
        {
            KeyConfigECParams *ecParams = dynamic_cast<KeyConfigECParams *>(conf.params().get());
            if (ecParams->ecCurveType() == "PRIME256v1")
            {
                return Keys::generateEC (ECKeyType::PRIME256V1);
            }
        }
        throw std::runtime_error ("Invalid key type");
    }

    // TODO: ask security wallet to store the certificate
    static void store (const CertificateX509 & cert, const StorageConfig & conf)
    {
    }


    std::string CertificateGeneratorServer::handleGenerateSelfsignedCertificate(const fty::Payload & params)
    {
        if (params.empty() || params[0].empty ())
        {
            throw std::runtime_error ("Missing service name");
        }

        std::string serviceName (params[0]);
        CertificateGeneratorConfig certgenConfig = getConfig(m_configPath, serviceName);

        fty::CertificateConfig config = loadConfig (certgenConfig.version(), certgenConfig.certConf());

        store (CertificateX509::selfSignSha256(generateKeys(certgenConfig.keyConf()), config), certgenConfig.storageConf());
        return "OK";
    }

    std::string CertificateGeneratorServer::handleGenerateCSR(const fty::Payload & params)
    {
        if (params.empty() || params[0].empty ())
        {
            throw std::runtime_error ("Missing service name");
        }

        std::string serviceName (params[0]);
        CertificateGeneratorConfig certgenConfig = getConfig(m_configPath, serviceName);

        fty::CertificateConfig config = loadConfig (certgenConfig.version(), certgenConfig.certConf());

        fty::Keys keyPair(generateKeys(certgenConfig.keyConf()));

        fty::CsrX509 csr = CsrX509::generateCsr(keyPair, config);

        // replace existing csr for a given service, if any
        m_csrPending.erase(serviceName);    // delete old request
        m_csrPending.insert({serviceName, csr});

        return csr.getPem();
    }

    std::string CertificateGeneratorServer::handleImportCertificate(const fty::Payload & params)
    {
        if (params.size() != 2)
        {
            throw std::runtime_error ("Wrong number of parameters");
        }
        else if (params[0].empty ())
        {
            throw std::runtime_error ("Empty service name");
        }
        else if (params[1].empty ())
        {
            throw std::runtime_error ("Empty certificate PEM");
        }
       
        std::string serviceName (params[0]);
        std::string certPem (params[1]);

        auto searchPendingCsr = m_csrPending.find(serviceName);

        if (searchPendingCsr == m_csrPending.end())
        {
            throw std::runtime_error ("No pending CSR request for service " + serviceName);
        }

        CertificateGeneratorConfig certgenConfig = getConfig(m_configPath, serviceName);

        fty::CertificateConfig config = loadConfig (certgenConfig.version(), certgenConfig.certConf());

        fty::CertificateX509 tmpCert(certPem);

        if (tmpCert.getPublicKey() != searchPendingCsr->second.getPublicKey())
        {
            throw std::runtime_error("Imported key does not match the signature of the pending CRS");
        }
        
        m_csrPending.erase(serviceName);

        store (tmpCert, certgenConfig.storageConf());
        return "OK";
    }

    std::string CertificateGeneratorServer::handleGetPendingCSR(const fty::Payload & params)
    {
        if (params.empty() || params[0].empty ())
        {
            throw std::runtime_error ("Missing service name");
        }
       
        std::string serviceName (params[0]);

        auto searchPendingCsr = m_csrPending.find(serviceName);

        if (searchPendingCsr == m_csrPending.end())
        {
            throw std::runtime_error ("No pending CSR request for service " + serviceName);
        }

        return m_csrPending.at(serviceName).getPem();
    }

    std::string CertificateGeneratorServer::handleRemovePendingCSR(const fty::Payload & params)
    {
        if (params.empty() || params[0].empty ())
        {
            throw std::runtime_error ("Missing service name");
        }
       
        std::string serviceName (params[0]);

        m_csrPending.erase(serviceName);
        
        return "OK";
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

void
certgen_certificate_generator_server_test (bool verbose)
{
    using namespace certgen;

    // env vars
    setenv("ENV_KNOWNFQDNS", "mauro.roz.lab.etn.com", 1);

    std::vector<std::pair<std::string, bool>> testsResults;

    std::string testNumber;
    std::string testName;

    printf (" * certgen_certificate_generator_server: ");

    using Arguments = std::map<std::string, std::string>;
    
    printf ("\n ** fty_credential_asset_mapping_mlm_agent: \n");
    assert (SELFTEST_DIR_RO);
    assert (SELFTEST_DIR_RW);

    static const char* endpoint = "inproc://certgen-certificate-generator-server";

    zactor_t *broker = zactor_new (mlm_server, (void*) "Malamute");
    zstr_sendx (broker, "BIND", endpoint, NULL);
    if (verbose)
        zstr_send (broker, "VERBOSE");
    
    //set configuration parameters
    Arguments agentParams;

    agentParams["AGENT_NAME"] = "certgen-test-agent";
    agentParams["CONFIG_PATH"] = SELFTEST_DIR_RO"/cfg/";
    agentParams["ENDPOINT"] = endpoint;

    //start broker agent
    zactor_t *server = zactor_new (fty_certificate_generator_agent, static_cast<void*>(&agentParams));

    {
        //create the 1 Client
        mlm::MlmSyncClient syncClient("certgen-accessor-test", "certgen-test-agent", 1000, endpoint);

        //Tests from the lib
        std::vector<std::pair<std::string,bool>> testLibResults = certgen_accessor_test(syncClient);

        printf("\n-----------------------------------------------------------------------\n");

        uint32_t testsPassed = 0;
        uint32_t testsFailed = 0;

        printf ("\n ** fty_certificate_generator_agent: \n");

        printf("\tTests from the accessor: \n");
        for(const auto & result : testLibResults)
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

            /*std::ifstream database(SELFTEST_DIR_RW"/mapping.json", std::ios::binary);
            std::cerr << database.rdbuf() << std::endl;

            database.close();*/
        }
        else
        {
            printf(ANSI_COLOR_RED"\n!!!!!!!! %i/%i tests did not pass !!!!!!!! \n" ANSI_COLOR_RESET "\n",testsFailed,(testsPassed+testsFailed));
            assert(false);
        }


        zstr_sendm (server, "$TERM");
        sleep(1);

    }

    zactor_destroy (&server);
    zactor_destroy (&broker);
}
