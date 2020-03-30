/*  =========================================================================
    fty_certificate_generator_agent - class description

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
    fty_certificate_generator_agent -
@discuss
@end
*/

#include "fty_certificate_generator_classes.h"

void fty_certificate_generator_agent(zsock_t *pipe, void *args)
{
    using Arguments = std::map<std::string, std::string>;

    const Arguments & arguments = *static_cast<Arguments*>(args);

    //create the server
    certgen::CertificateGeneratorServer server(
                                       arguments.at("CONFIG_PATH"),
                                       arguments.at("SECW_SOCKET")
                                    );

    //launch the agent
    mlm::MlmBasicMailboxServer agent(  pipe,
                                       server,
                                       arguments.at("AGENT_NAME"),
                                       arguments.at("ENDPOINT")
                                    );
    agent.mainloop();
}

//  --------------------------------------------------------------------------
//  Self test of this class
#define SELFTEST_DIR_RO "src/selftest-ro"
#define SELFTEST_DIR_RW "src/selftest-rw"

void
fty_certificate_generator_agent_test (bool verbose)
{
    printf (" * fty_certificate_generator_agent: ");

    //  @selftest
    //  Simple create/destroy test
    //  @end
    printf ("OK\n");
}
