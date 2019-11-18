/*  =========================================================================
    certgen_storage_config - class description

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

#ifndef CERTGEN_STORAGE_CONFIG_H_INCLUDED
#define CERTGEN_STORAGE_CONFIG_H_INCLUDED

#include <string>
#include <vector>
#include <memory>
#include <ostream>

#include "cxxtools/serializationinfo.h"
#include "cxxtools/jsondeserializer.h"

namespace certgen
{
    class StorageConfigParams;
    using StorageConfigParamsPtr = std::unique_ptr<StorageConfigParams>;

    class StorageConfig
    {
    private:
        std::string m_storageType;
        bool m_permanent;
        StorageConfigParamsPtr m_params;

    public:
        StorageConfig() = default;

        void load(const cxxtools::SerializationInfo& si);

        const std::string & storageType() const { return m_storageType; }
        bool isPermanent() const { return m_permanent; }
        const StorageConfigParamsPtr & params() const { return m_params; }
    };
    void operator>>= (const cxxtools::SerializationInfo& si, StorageConfig & config);
    std::ostream& operator<<(std::ostream& os, const StorageConfig & s);

    class StorageConfigParams
    {
    public:
        virtual ~StorageConfigParams() = default;
        virtual void load(const cxxtools::SerializationInfo& si) = 0;

        virtual std::string toString() const = 0;

        static StorageConfigParamsPtr create(const std::string & storageType);
    };
    void operator>>= (const cxxtools::SerializationInfo& si, StorageConfigParams & config);

    class StorageConfigSecwParams : public StorageConfigParams
    {
    private:
        std::string m_portfolio;
        std::string m_documentName;
        std::vector<std::string> m_documentUsages;
    public:

        void load(const cxxtools::SerializationInfo& si) override;

        std::string toString() const override;

        const std::string & portfolio() const { return m_portfolio; }
        const std::string & documentName() const { return m_documentName; }
        const std::vector<std::string> & documentUsages() const { return m_documentUsages; }
    };

    class StorageConfigFileParams : public StorageConfigParams
    {
    private:
        std::string m_fileCertificatePath;
        std::string m_fileCertificateFormat;
        std::string m_fileKeyPath;
        std::string m_fileKeyFormat;
    public:

        void load(const cxxtools::SerializationInfo& si) override;

        std::string toString() const override;

        const std::string & fileCertificatePath()   const { return m_fileCertificatePath; }
        const std::string & fileCertificateFormat() const { return m_fileCertificateFormat; }
        const std::string & fileKeyPath()           const { return m_fileKeyPath; }
        const std::string & fileKeyFormat()         const { return m_fileKeyFormat; }
    };

} //namespace certgen

void certgen_storage_config_test (bool verbose);

#endif
