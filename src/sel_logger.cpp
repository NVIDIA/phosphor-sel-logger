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
#include <systemd/sd-journal.h>

#include <boost/algorithm/string.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/container/flat_set.hpp>
#include <boost/format.hpp>
#include <pulse_event_monitor.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sel_logger.hpp>
#include <threshold_event_monitor.hpp>
#include <cable_event_monitor.hpp>
#include <watchdog_event_monitor.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#ifdef SEL_LOGGER_MONITOR_THRESHOLD_ALARM_EVENTS
#include <threshold_alarm_event_monitor.hpp>
#endif

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

#ifdef SEL_LOGGER_SEND_TO_LOGGING_SERVICE
#include <xyz/openbmc_project/Logging/SEL/error.hpp>

using namespace phosphor::logging;
using SELCreated =
    sdbusplus::xyz::openbmc_project::Logging::SEL::Error::Created;
#endif

// Keep track for reaching max sel events
#ifndef SEL_LOGGER_SEND_TO_LOGGING_SERVICE
static bool maxSELEntriesReached = false;
#endif
struct DBusInternalError final : public sdbusplus::exception_t
{
    const char* name() const noexcept override
    {
        return "org.freedesktop.DBus.Error.Failed";
    }
    const char* description() const noexcept override
    {
        return "internal error";
    }
    const char* what() const noexcept override
    {
        return "org.freedesktop.DBus.Error.Failed: "
               "internal error";
    }

    int get_errno() const noexcept override
    {
        return EACCES;
    }
};

#ifndef SEL_LOGGER_SEND_TO_LOGGING_SERVICE
static bool getSELLogFiles(std::vector<std::filesystem::path>& selLogFiles)
{
    // Loop through the directory looking for ipmi_sel log files
    for (const std::filesystem::directory_entry& dirEnt :
         std::filesystem::directory_iterator(selLogDir))
    {
        std::string filename = dirEnt.path().filename();
        if (boost::starts_with(filename, selLogFilename))
        {
            // If we find an ipmi_sel log file, save the path
            selLogFiles.emplace_back(selLogDir / filename);
        }
    }
    // As the log files rotate, they are appended with a ".#" that is higher for
    // the older logs. Since we don't expect more than 10 log files, we
    // can just sort the list to get them in order from newest to oldest
    std::sort(selLogFiles.begin(), selLogFiles.end());

    return !selLogFiles.empty();
}

static bool isLinearSELPolicy()
{
    auto bus = sdbusplus::bus::new_default();

    try
    {
        // IPMI SEL Policy Object
        auto method = bus.new_method_call(selLogObj, selLogPath,
                        "org.freedesktop.DBus.Properties", "Get");
        method.append(selLogIntf, "SelPolicy");
        auto reply = bus.call(method);
        if (reply.is_method_error())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "isLinearSELPolicy: Failed to read sel policy",
                phosphor::logging::entry("PATH=%s", selLogPath),
                phosphor::logging::entry("INTERFACE=%s", selLogIntf));
            return false;
        }

        std::variant<std::string> value;
        reply.read(value);

        if (std::get<std::string>(value) ==
            "xyz.openbmc_project.Logging.Settings.Policy.Linear")
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "isLinearSELPolicy: Failed to get sel policy",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return false;
    }
}

#ifndef SEL_LOGGER_SEND_TO_LOGGING_SERVICE
static std::string getSELEventStr(const unsigned int& recordId, const std::string& selDataStr,
                                  const uint16_t& genId, const std::string& path, const bool& assert)
{
    // The format of the ipmi_sel message is:
    // "<Timestamp> <ID>,<Type>,<EventData>,[<Generator ID>,<Path>,<Direction>]"

    // Get the timestamp
    time_t t;
    struct tm *tmp;
    char timestamp[30];
    time( &t );
    tmp = localtime( &t );
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", tmp);

    // Create SEL event string
    std::string selStr;
    try
    {
        selStr = (boost::format("%s %d,%d,%s,%x,%s,%x") % timestamp % recordId %
            static_cast<size_t>(selSystemType) % selDataStr.c_str() % genId %
            path.c_str() % assert)
            .str();
    }
    catch (...)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getSELEventStr: Failed to format SEL event string");
    }
    return selStr;
}
#endif

static unsigned int initializeRecordId(void)
{
    std::vector<std::filesystem::path> selLogFiles;
    if (!getSELLogFiles(selLogFiles))
    {
        return selInvalidRecID;
    }
    std::ifstream logStream(selLogFiles.front());
    if (!logStream.is_open())
    {
        return selInvalidRecID;
    }
    std::string line;
    std::string newestEntry;
    while (std::getline(logStream, line))
    {
        newestEntry = line;
    }

    std::vector<std::string> newestEntryFields;
    boost::split(newestEntryFields, newestEntry, boost::is_any_of(" ,"),
                 boost::token_compress_on);
    if (newestEntryFields.size() < 4)
    {
        return selInvalidRecID;
    }

    unsigned int id = std::stoul(newestEntryFields[1]);
    // Update max sel entry reached flag on startup
    if (id >= maxSELEntries)
    {
        maxSELEntriesReached = true;
    }

    return id;
}

#ifdef SEL_LOGGER_CLEARS_SEL
static unsigned int recordId = initializeRecordId();

void clearSelLogFiles()
{
    // Clear the SEL by deleting the log files
    std::vector<std::filesystem::path> selLogFiles;
    if (getSELLogFiles(selLogFiles))
    {
        for (const std::filesystem::path& file : selLogFiles)
        {
            std::error_code ec;
            std::filesystem::remove(file, ec);
        }
    }

    recordId = selInvalidRecID;

    // Reload rsyslog so it knows to start new log files
    boost::asio::io_service io;
    auto dbus = std::make_shared<sdbusplus::asio::connection>(io);
    sdbusplus::message::message rsyslogReload = dbus->new_method_call(
        "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "ReloadUnit");
    rsyslogReload.append("rsyslog.service", "replace");
    try
    {
        sdbusplus::message::message reloadResponse = dbus->call(rsyslogReload);
    }
    catch (const sdbusplus::exception_t& e)
    {
        std::cerr << e.what() << "\n";
    }
}
#endif

static unsigned int getNewRecordId(void)
{
#ifndef SEL_LOGGER_CLEARS_SEL
    static unsigned int recordId = initializeRecordId();

    // If the log has been cleared, also clear the current ID
    std::vector<std::filesystem::path> selLogFiles;
    if (!getSELLogFiles(selLogFiles))
    {
        recordId = selInvalidRecID;
    }
#endif

    // Do not increase recordID on reaching maxSELEntries in linear sel config
    if (maxSELEntriesReached && isLinearSELPolicy())
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Skip SEL event write on reaching max SEL entries in linear config");
        return 0;
    }

    if (++recordId >= selInvalidRecID)
    {
        recordId = 1;
    }
    return recordId;
}
#endif

static void toHexStr(const std::vector<uint8_t>& data, std::string& hexStr)
{
    std::stringstream stream;
    stream << std::hex << std::uppercase << std::setfill('0');
    for (int v : data)
    {
        stream << std::setw(2) << v;
    }
    hexStr = stream.str();
}
#ifndef SEL_LOGGER_SEND_TO_LOGGING_SERVICE
static void circularConfEventsRotate(std::filesystem::path selLogFile)
{
    std::string line;
    std::ifstream fromStream(selLogFile);
    if (!fromStream.is_open())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "circularConfEventsRotate: Failed to open SEL log file");
        return;
    }
    std::ofstream toStream;
    std::filesystem::path selLogFileBackup = selLogDir / "ipmi_sel_backup";
    toStream.open(selLogFileBackup, std::ios_base::app | std::ios_base::out);
    // Skip the first line
    getline(fromStream, line);
    while( getline(fromStream, line) )
    {
        toStream << line << "\n";
    }
    // Close files
    fromStream.close();
    toStream.close();
    // Replace original file
    remove(selLogFile);
    rename(selLogFileBackup, selLogFile);

    return;
}


static void writeSELEvent(const unsigned int& recordId, const std::string& selDataStr,
                          const uint16_t& genId, const std::string& path, const bool& assert)
{
    // Write the event
    // Format the SEL event string
    std::string selStr = getSELEventStr(recordId, selDataStr, genId,
                            path, assert);
    if (selStr.empty())
    {
        // No write for empty string
        return;
    }

    // Get the SEL event log file
    std::vector<std::filesystem::path> selLogFiles;
    std::filesystem::path selLogFile;
    if (!getSELLogFiles(selLogFiles))
    {
        // Create the file
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "writeSELEvent: Creating SEL log file");
        selLogFile = selLogDir / selLogFilename;
    }
    else
    {
        selLogFile = selLogFiles.front();
    }
    // Write the event to SEL log file
    std::ofstream logStream(selLogFile, std::ios_base::app | std::ios_base::out);
    if (!logStream.is_open())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
           "writeSELEvent: Failed to open SEL log file");
        return;
    }
    logStream<<selStr<<'\n';
    logStream.close();

    // Check for Max SEL entries for circular config
    if (maxSELEntriesReached && !isLinearSELPolicy())
    {
        // Delete the first event
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Remove first SEL event on reaching max SEL entries in circular config");
        circularConfEventsRotate(selLogFile);
    }

    return;
}
#endif
#ifdef SEL_LOGGER_SEND_TO_LOGGING_SERVICE
std::string getService(sdbusplus::bus::bus& bus, const std::string& path,
                       const std::string& interface)
{
    auto method = bus.new_method_call(mapperBus, mapperPath, mapperInterface,
                                      "GetObject");

    method.append(path);
    method.append(std::vector<std::string>({interface}));

    auto reply = bus.call(method);

    std::map<std::string, std::vector<std::string>> response;
    reply.read(response);

    if (response.empty())
    {
        log<level::ERR>("Error in mapper response for getting service name",
                        entry("PATH=%s", path.c_str()),
                        entry("INTERFACE=%s", interface.c_str()));
        return std::string{};
    }

    return response.begin()->first;
}
#endif
#ifdef SEL_LOGGER_SEND_TO_LOGGING_SERVICE
static void selAddSystemRecord(const std::string& messageID,
                               const std::string& message,
                               const std::string& path,
                               const std::vector<uint8_t>& selData,
                               const bool& assert, const uint16_t& genId)
#else
template <typename... T>
static uint16_t selAddSystemRecord([[maybe_unused]] const std::string& message,
                                   const std::string& path,
                                   const std::vector<uint8_t>& selData,
                                   const bool& assert, const uint16_t& genId,
                                   [[maybe_unused]] T&&... metadata)
#endif
{
    // Only 3 bytes of SEL event data are allowed in a system record
    if (selData.size() > selEvtDataMaxSize)
    {
        throw std::invalid_argument("Event data too large");
    }
    std::string selDataStr;
    toHexStr(selData, selDataStr);

#ifdef SEL_LOGGER_SEND_TO_LOGGING_SERVICE

    auto sevLvl = ErrLvl::Informational;
    static auto bus = sdbusplus::bus::new_default();
    std::map<std::string, std::string> addData;
    addData["namespace"] = "SEL";
    addData["REDFISH_MESSAGE_ID"] = messageID.c_str();
    addData["REDFISH_MESSAGE_ARGS"] = message.c_str();
    addData["SENSOR_DATA"] = selDataStr.c_str();
    addData["SENSOR_PATH"] = path.c_str();
    addData["EVENT_DIR"] = std::to_string(assert);
    addData["GENERATOR_ID"] = std::to_string(genId);
    addData["RECORD_TYPE"] = std::to_string(selSystemType);

    try
    {
        auto service = getService(bus, logObjPath, logInterface);
        auto method = bus.new_method_call(service.c_str(), logObjPath,
                                          logInterface, "Create");
        method.append(messageID, sevLvl, addData);
        bus.call_noreply(method);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Failed to create D-Bus log entry for SEL, ERROR="
                  << e.what() << "\n";
    }
    return;
#else
    unsigned int recordId = getNewRecordId();
    sd_journal_send("MESSAGE=%s", message.c_str(), "PRIORITY=%i", selPriority,
                    "MESSAGE_ID=%s", selMessageId, "IPMI_SEL_RECORD_ID=%d",
                    recordId, "IPMI_SEL_RECORD_TYPE=%x", selSystemType,
                    "IPMI_SEL_GENERATOR_ID=%x", genId,
                    "IPMI_SEL_SENSOR_PATH=%s", path.c_str(),
                    "IPMI_SEL_EVENT_DIR=%x", assert, "IPMI_SEL_DATA=%s",
                    selDataStr.c_str(), std::forward<T>(metadata)..., NULL);

    // Write SEL event record to ipmi_sel log file
    if (recordId != 0)
    {
        writeSELEvent(recordId, selDataStr, genId, path, assert);
        // Update max sel entry reached once recordId crosses maxSELEntries
        if (recordId >= maxSELEntries)
        {
            maxSELEntriesReached = true;
        }
        else
        {
            maxSELEntriesReached = false;
        }
    }

    return recordId;
#endif
}

static uint16_t selAddOemRecord([[maybe_unused]] const std::string& message,
                                const std::vector<uint8_t>& selData,
                                const uint8_t& recordType)
{
    // A maximum of 13 bytes of SEL event data are allowed in an OEM record
    if (selData.size() > selOemDataMaxSize)
    {
        throw std::invalid_argument("Event data too large");
    }
    std::string selDataStr;
    toHexStr(selData, selDataStr);

#ifdef SEL_LOGGER_SEND_TO_LOGGING_SERVICE
    using namespace xyz::openbmc_project::Logging::SEL;
    auto entryID = report<SELCreated>(
        Created::RECORD_TYPE(recordType), Created::GENERATOR_ID(0),
        Created::SENSOR_DATA(selDataStr.c_str()), Created::EVENT_DIR(0),
        Created::SENSOR_PATH(""));
    return static_cast<uint16_t>(entryID);
#else
    unsigned int recordId = getNewRecordId();
    sd_journal_send("MESSAGE=%s", message.c_str(), "PRIORITY=%i", selPriority,
                    "MESSAGE_ID=%s", selMessageId, "IPMI_SEL_RECORD_ID=%d",
                    recordId, "IPMI_SEL_RECORD_TYPE=%x", recordType,
                    "IPMI_SEL_DATA=%s", selDataStr.c_str(), NULL);
    return recordId;
#endif
}

int main(int, char*[])
{
    // setup connection to dbus
    boost::asio::io_service io;
    auto conn = std::make_shared<sdbusplus::asio::connection>(io);

    // IPMI SEL Object
    conn->request_name(ipmiSelObject);
    auto server = sdbusplus::asio::object_server(conn);

    // Add SEL Interface
    std::shared_ptr<sdbusplus::asio::dbus_interface> ifaceAddSel =
        server.add_interface(ipmiSelPath, ipmiSelAddInterface);
#ifdef SEL_LOGGER_SEND_TO_LOGGING_SERVICE
    ifaceAddSel->register_method(
        "IpmiSelAdd",
        [](const std::string& messageID, const std::string& message,
           const std::string& path, const std::vector<uint8_t>& selData,
           const bool& assert, const uint16_t& genId) {
            return selAddSystemRecord(messageID, message, path, selData, assert,
                                      genId);
        });
#else
    // Add a new SEL entry
    ifaceAddSel->register_method(
        "IpmiSelAdd", [](const std::string& message, const std::string& path,
                         const std::vector<uint8_t>& selData,
                         const bool& assert, const uint16_t& genId) {
            return selAddSystemRecord(message, path, selData, assert, genId);
        });
#endif
    // Add a new OEM SEL entry
    ifaceAddSel->register_method(
        "IpmiSelAddOem",
        [](const std::string& message, const std::vector<uint8_t>& selData,
           const uint8_t& recordType) {
            return selAddOemRecord(message, selData, recordType);
        });

#ifdef SEL_LOGGER_CLEARS_SEL
#ifndef SEL_LOGGER_SEND_TO_LOGGING_SERVICE
    // Clear SEL entries
    ifaceAddSel->register_method("Clear", []() { clearSelLogFiles(); });
#endif
#endif
    ifaceAddSel->initialize();

#ifdef SEL_LOGGER_MONITOR_THRESHOLD_EVENTS
    sdbusplus::bus::match::match thresholdAssertMonitor =
        startThresholdAssertMonitor(conn);
#endif  

#ifdef SEL_LOGGER_MONITOR_CABLE_EVENTS
    sdbusplus::bus::match::match cableAssertMonitor =
        startCableAssertMonitor(conn);
#endif

#ifdef REDFISH_LOG_MONITOR_PULSE_EVENTS
    sdbusplus::bus::match::match pulseEventMonitor =
        startPulseEventMonitor(conn);
#endif

#ifdef SEL_LOGGER_MONITOR_WATCHDOG_EVENTS
    sdbusplus::bus::match::match watchdogEventMonitor =
        startWatchdogEventMonitor(conn);
#endif

#ifdef SEL_LOGGER_MONITOR_THRESHOLD_ALARM_EVENTS
    startThresholdAlarmMonitor(conn);
#endif
    io.run();

    return 0;
}
