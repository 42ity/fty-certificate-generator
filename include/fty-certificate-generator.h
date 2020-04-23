/*  =========================================================================
    fty-certificate-generator - Generation internal certificates agent

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

#ifndef FTY_CERTIFICATE_GENERATOR_H_H_INCLUDED
#define FTY_CERTIFICATE_GENERATOR_H_H_INCLUDED

//  Include the project library file
#include "fty_certificate_generator_library.h"

// common command list for certgen
namespace certgen
{
    static constexpr const char* GET_SERVICES_LIST = "GET_SERVICES_LIST";
    static constexpr const char* GENERATE_SELFSIGNED_CERTIFICATE = "GENERATE_SELFSIGNED_CERTIFICATE";
    static constexpr const char* GENERATE_CSR = "GENERATE_CSR";
    static constexpr const char* IMPORT_CERTIFICATE = "IMPORT_CERTIFICATE";
    static constexpr const char* GET_CERTIFICATE = "GET_CERTIFICATE";
    static constexpr const char* GET_PENDING_CSR = "GET_PENDING_CSR";
    static constexpr const char* GET_PENDING_CSR_CREAT_DATE = "GET_PENDING_CSR_CREAT_DATE";
    static constexpr const char* REMOVE_PENDING_CSR = "REMOVE_PENDING_CSR";
}

#endif
