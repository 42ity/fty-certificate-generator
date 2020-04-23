/*  =========================================================================
    certgen_key_config - class description

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

#ifndef CERTGEN_KEY_CONFIG_H_INCLUDED
#define CERTGEN_KEY_CONFIG_H_INCLUDED

#include <string>
#include <vector>
#include <memory>
#include <ostream>

#include "cxxtools/serializationinfo.h"
#include "cxxtools/jsondeserializer.h"

namespace certgen
{
    class KeyConfigParams;
    using KeyConfigParamsPtr = std::unique_ptr<KeyConfigParams>;

    class KeyConfig
    {
    private:
        std::string m_keyType;
        KeyConfigParamsPtr m_params;

    public:
        KeyConfig() = default;

        void load(const cxxtools::SerializationInfo& si);

        const std::string & keyType() const { return m_keyType; }
        const KeyConfigParamsPtr & params() const { return m_params; }
    };
    void operator>>= (const cxxtools::SerializationInfo& si, KeyConfig & config);
    std::ostream& operator<<(std::ostream& os, const KeyConfig & k);

    class KeyConfigParams
    {
    public:
        virtual ~KeyConfigParams() = default;
        virtual void load(const cxxtools::SerializationInfo& si) = 0;

        virtual std::string toString() const = 0;

        static KeyConfigParamsPtr create(const std::string & storageType);
    };
    void operator>>= (const cxxtools::SerializationInfo& si, KeyConfigParams & config);

    class KeyConfigRsaParams : public KeyConfigParams
    {
    private:
        int m_rsaLength;

    public:
        void load(const cxxtools::SerializationInfo& si) override;
        std::string toString() const override;
        int rsaLength() { return m_rsaLength; }
    };

    class KeyConfigECParams : public KeyConfigParams
    {
    private:
        std::string m_ecCurveType;

    public:
        void load(const cxxtools::SerializationInfo& si) override;
        std::string toString() const override;
        const std::string & ecCurveType() const { return m_ecCurveType; }
    };

} //namespace certgen

void certgen_key_config_test (bool verbose);

#endif
