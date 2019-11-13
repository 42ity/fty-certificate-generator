/*  =========================================================================
    fty-certificate-generator - description

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
    fty-certificate-generator -
@discuss
@end
*/

#include "fty_certificate_generator_classes.h"

#define DEFAULT_ENDPOINT      "ipc://@/malamute"

int main (int argc, char *argv [])
{
    using Arguments = std::map<std::string, std::string>;
    bool verbose = false;
    int argn;
    for (argn = 1; argn < argc; argn++) {
        if (streq (argv [argn], "--help")
        ||  streq (argv [argn], "-h")) {
            puts ("fty-certificate-generator [options] ...");
            puts ("  --verbose / -v         verbose test output");
            puts ("  --help / -h            this information");
            return 0;
        }
        else
        if (streq (argv [argn], "--verbose")
        ||  streq (argv [argn], "-v"))
            verbose = true;
        else {
            printf ("Unknown option: %s\n", argv [argn]);
            return 1;
        }
    }

    if (verbose)
    {
        log_info ("fty-certificate-generator - ");
    }

//  Insert main code here
    Arguments paramsCertgen;

    paramsCertgen["AGENT_NAME"] = "fty-certificate-generator";
    paramsCertgen["CONFIG_PATH"] = "/etc/fty/fty-certificate-generator/";
    paramsCertgen["ENDPOINT"] = DEFAULT_ENDPOINT;
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
