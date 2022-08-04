/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#pragma once
#include <filesystem>

static constexpr char const* ipmiSelObject = "xyz.openbmc_project.Logging.IPMI";
static constexpr char const* ipmiSelPath = "/xyz/openbmc_project/Logging/IPMI";
static constexpr char const* ipmiSelAddInterface =
    "xyz.openbmc_project.Logging.IPMI";
// SEL policy in dbus
static constexpr char const *selLogObj = "xyz.openbmc_project.Settings";
static constexpr char const *selLogPath = "/xyz/openbmc_project/logging/settings";
static constexpr char const *selLogIntf = "xyz.openbmc_project.Logging.Settings";

// ID string generated using journalctl to include in the MESSAGE_ID field for
// SEL entries.  Helps with filtering SEL entries in the journal.
static constexpr char const* selMessageId = "b370836ccf2f4850ac5bee185b77893a";
static constexpr int selPriority = 5; // notice
static constexpr uint8_t selSystemType = 0x02;
static constexpr uint16_t selBMCGenID = 0x0020;
static constexpr uint16_t selInvalidRecID =
    std::numeric_limits<uint16_t>::max();
static constexpr size_t selEvtDataMaxSize = 3;
static constexpr size_t selOemDataMaxSize = 13;
static constexpr uint8_t selEvtDataUnspecified = 0xFF;
// Max 3K SEL entries
static constexpr int maxSELEntries = 3000;

static const std::filesystem::path selLogDir = "/var";
static const std::string selLogFilename = "ipmi_sel";
#ifdef SEL_LOGGER_SEND_TO_LOGGING_SERVICE
#include "xyz/openbmc_project/Logging/Entry/server.hpp"

#include <xyz/openbmc_project/Logging/SEL/error.hpp>
using ErrLvl = sdbusplus::xyz::openbmc_project::Logging::server::Entry::Level;

static void selAddSystemRecord(const std::string& messageID,
                               const std::string& message,
                               const std::string& path,
                               const std::vector<uint8_t>& selData,
                               const bool& assert, const uint16_t& genId);

std::string getService(const std::string& path, const std::string& interface);
constexpr auto mapperBus = "xyz.openbmc_project.ObjectMapper";
constexpr auto mapperPath = "/xyz/openbmc_project/object_mapper";
constexpr auto mapperInterface = "xyz.openbmc_project.ObjectMapper";
static constexpr auto logObjPath = "/xyz/openbmc_project/logging";
static constexpr auto logInterface = "xyz.openbmc_project.Logging.Create";
#else
template <typename... T>
static uint16_t
    selAddSystemRecord(const std::string& message, const std::string& path,
                       const std::vector<uint8_t>& selData, const bool& assert,
                       const uint16_t& genId, T&&... metadata);
#endif
