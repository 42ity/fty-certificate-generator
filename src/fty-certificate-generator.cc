/*  =========================================================================
    fty-certificate-generator - description

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
    fty-certificate-generator -
@discuss
@end
*/

#include "fty_certificate_generator_classes.h"

#define DEFAULT_ENDPOINT      "ipc://@/malamute"
#define DEFAULT_CONFIG_PATH   "/usr/share/fty-certificate-generator/"
#define FTY_CERTGEN_AGENT     "fty-certificate-generator"

int main (int argc, char *argv [])
{
    using Arguments = std::map<std::string, std::string>;
    char *config_file = NULL;

    // Initialize logging, to console first
    const char *logConfigFile = "";
    ftylog_setInstance(FTY_CERTGEN_AGENT, "");

    bool verbose = false;
    int argn;
    // Parse command line
    for (argn = 1; argn < argc; argn++) {
        char *param = NULL;
        if (argn < argc - 1) param = argv [argn+1];

        if (streq (argv [argn], "--help")
        ||  streq (argv [argn], "-h")) {
            puts ("fty-certificate-generator [options] ...");
            puts ("  --verbose / -v         verbose test output");
            puts ("  --help / -h            this information");
            puts ("  -c|--config            path to config file");
            return 0;
        }
        else
        if (streq (argv [argn], "--verbose")
        ||  streq (argv [argn], "-v")) {
            verbose = true;
        }
        else
        if (streq (argv [argn], "--config")
        ||  streq (argv [argn], "-c")) {
            if (param) config_file = param;
            ++argn;
        }
        else {
            printf ("Unknown option: %s\n", argv [argn]);
            return 1;
        }
    }

    if (verbose)
    {
        log_info ("fty-certificate-generator - initializing");
    }

//  Insert main code here
    Arguments paramsCertgen;

    paramsCertgen["AGENT_NAME"] = FTY_CERTGEN_AGENT;
    paramsCertgen["CONFIG_PATH"] = DEFAULT_CONFIG_PATH; // not the generic config files, but cert-gen specific config
    paramsCertgen["ENDPOINT"] = DEFAULT_ENDPOINT; // malamute
    paramsCertgen["SECW_SOCKET"] = ""; // use default

// Parse generic config file, if any
    if(config_file)
    {
        log_debug (SECURITY_WALLET_AGENT ": loading configuration file from '%s' ...", config_file);
        mlm::ZConfig config(config_file);

        verbose |= (config.getEntry("server/verbose", "false") == "true");

        paramsCertgen["CONFIG_PATH"] = config.getEntry("certgen-storage/config-path", DEFAULT_CONFIG_PATH);
        paramsCertgen["ENDPOINT"] = config.getEntry("secw-malamute/endpoint", DEFAULT_ENDPOINT);
        paramsCertgen["SECW_SOCKET"] = config.getEntry("secw-socket/socket", "");

        logConfigFile = config.getEntry("log/config", "").c_str();
    }

    //If a log config file is configured, try to load it
    if (!streq(logConfigFile, ""))
    {
      log_debug("Try to load log configuration file : %s", logConfigFile);
      ftylog_setConfigFile(ftylog_getInstance(), logConfigFile);
    }

    if (verbose)
    {
        ftylog_setVerboseMode(ftylog_getInstance());
        log_info ("fty-certificate-generator - configuration parsed");
    }

    zactor_t *certgen_server = zactor_new (fty_certificate_generator_agent,  static_cast<void*>(&paramsCertgen));

    while (true)
    {
        char *str = zstr_recv (certgen_server);
        if (str)
        {
            puts (str);
            zstr_free (&str);
        }
        else
        {
            //stop everything
            break;
        }
    }

    zactor_destroy(&certgen_server);
    return 0;
}
