/*
// Copyright (c) 2021 Intel Corporation
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
#include "threshold_event_monitor.hpp"

#include <boost/container/flat_map.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sel_logger.hpp>
#include <sensorutils.hpp>

#include <format>
#include <map>
#include <optional>
#include <string_view>
#include <variant>

using sdbusMatch = std::shared_ptr<sdbusplus::bus::match_t>;
static sdbusMatch warningLowAssertedMatcher;
static sdbusMatch warningLowDeassertedMatcher;
static sdbusMatch warningHighAssertedMatcher;
static sdbusMatch warningHighDeassertedMatcher;
static sdbusMatch criticalLowAssertedMatcher;
static sdbusMatch criticalLowDeassertedMatcher;
static sdbusMatch criticalHighAssertedMatcher;
static sdbusMatch criticalHighDeassertedMatcher;
#ifdef SEL_LOGGER_USE_DMTF_REGISTRY
static sdbusMatch hardShutdownLowAssertedMatcher;
static sdbusMatch hardShutdownLowDeassertedMatcher;
static sdbusMatch hardShutdownHighAssertedMatcher;
static sdbusMatch hardShutdownHighDeassertedMatcher;
#endif

static boost::container::flat_map<std::string, sdbusMatch> matchers = {
    {"WarningLowAlarmAsserted", warningLowAssertedMatcher},
    {"WarningLowAlarmDeasserted", warningLowDeassertedMatcher},
    {"WarningHighAlarmAsserted", warningHighAssertedMatcher},
    {"WarningHighAlarmDeasserted", warningHighDeassertedMatcher},
    {"CriticalLowAlarmAsserted", criticalLowAssertedMatcher},
    {"CriticalLowAlarmDeasserted", criticalLowDeassertedMatcher},
    {"CriticalHighAlarmAsserted", criticalHighAssertedMatcher},
    {"CriticalHighAlarmDeasserted", criticalHighDeassertedMatcher},
#ifdef SEL_LOGGER_USE_DMTF_REGISTRY
    {"HardShutdownLowAlarmAsserted", hardShutdownLowAssertedMatcher},
    {"HardShutdownLowAlarmDeasserted", hardShutdownLowDeassertedMatcher},
    {"HardShutdownHighAlarmAsserted", hardShutdownHighAssertedMatcher},
    {"HardShutdownHighAlarmDeasserted", hardShutdownHighDeassertedMatcher}
#endif
};

void generateEvent(std::string signalName,
                   std::shared_ptr<sdbusplus::asio::connection> conn,
                   sdbusplus::message_t &msg) {
  double assertValue;
  try {
    msg.read(assertValue);
  } catch (const sdbusplus::exception_t &) {
    std::cerr << "error getting assert signal data from " << msg.get_path()
              << "\n";
    return;
  }

  std::string event;
  std::string thresholdInterface;
  std::string threshold;
  std::string direction;
  bool assert = false;
  std::vector<uint8_t> eventData(selEvtDataMaxSize, selEvtDataUnspecified);
#ifdef SEL_LOGGER_USE_DMTF_REGISTRY
  std::string redfishMessageID = "SensorEvent." + dmtfMessageRegistryVersion;
#else
  std::string redfishMessageID = "OpenBMC." + openBMCMessageRegistryVersion;
#endif

  if (signalName == "WarningLowAlarmAsserted" ||
      signalName == "WarningLowAlarmDeasserted") {
    event = "WarningLow";
    thresholdInterface = "xyz.openbmc_project.Sensor.Threshold.Warning";
    eventData[0] =
        static_cast<uint8_t>(thresholdEventOffsets::lowerNonCritGoingLow);
    threshold = "warning low";
    if (signalName == "WarningLowAlarmAsserted") {
      assert = true;
      direction = "low";
#ifdef SEL_LOGGER_USE_DMTF_REGISTRY
      redfishMessageID += ".ReadingBelowLowerCautionThreshold";
#else
      redfishMessageID += ".SensorThresholdWarningLowGoingLow";
#endif
    } else if (signalName == "WarningLowAlarmDeasserted") {
      direction = "high";
#ifdef SEL_LOGGER_USE_DMTF_REGISTRY
      redfishMessageID += ".SensorReadingNormalRange";
#else
      redfishMessageID += ".SensorThresholdWarningLowGoingHigh";
#endif
    }
  } else if (signalName == "WarningHighAlarmAsserted" ||
             signalName == "WarningHighAlarmDeasserted") {
    event = "WarningHigh";
    thresholdInterface = "xyz.openbmc_project.Sensor.Threshold.Warning";
    eventData[0] =
        static_cast<uint8_t>(thresholdEventOffsets::upperNonCritGoingHigh);
    threshold = "warning high";
    if (signalName == "WarningHighAlarmAsserted") {
      assert = true;
      direction = "high";
#ifdef SEL_LOGGER_USE_DMTF_REGISTRY
      redfishMessageID += ".ReadingAboveUpperCautionThreshold";
#else
      redfishMessageID += ".SensorThresholdWarningHighGoingHigh";
#endif
    } else if (signalName == "WarningHighAlarmDeasserted") {
      direction = "low";
#ifdef SEL_LOGGER_USE_DMTF_REGISTRY
      redfishMessageID += ".SensorReadingNormalRange";
#else
      redfishMessageID += ".SensorThresholdWarningHighGoingLow";
#endif
    }
  } else if (signalName == "CriticalLowAlarmAsserted" ||
             signalName == "CriticalLowAlarmDeasserted") {
    event = "CriticalLow";
    thresholdInterface = "xyz.openbmc_project.Sensor.Threshold.Critical";
    eventData[0] =
        static_cast<uint8_t>(thresholdEventOffsets::lowerCritGoingLow);
    threshold = "critical low";
    if (signalName == "CriticalLowAlarmAsserted") {
      assert = true;
      direction = "low";
#ifdef SEL_LOGGER_USE_DMTF_REGISTRY
      redfishMessageID += ".ReadingBelowLowerCriticalThreshold";
#else
      redfishMessageID += ".SensorThresholdCriticalLowGoingLow";
#endif
    } else if (signalName == "CriticalLowAlarmDeasserted") {
      direction = "high";
#ifdef SEL_LOGGER_USE_DMTF_REGISTRY
      if (isOutsideNormalRange(conn, msg.get_sender(), msg.get_path())) {
        redfishMessageID += ".ReadingAboveLowerCriticalThreshold";
      } else {
        redfishMessageID += ".SensorReadingNormalRange";
      }
#else
      redfishMessageID += ".SensorThresholdCriticalLowGoingHigh";
#endif
    }
  } else if (signalName == "CriticalHighAlarmAsserted" ||
             signalName == "CriticalHighAlarmDeasserted") {
    event = "CriticalHigh";
    thresholdInterface = "xyz.openbmc_project.Sensor.Threshold.Critical";
    eventData[0] =
        static_cast<uint8_t>(thresholdEventOffsets::upperCritGoingHigh);
    threshold = "critical high";
    if (signalName == "CriticalHighAlarmAsserted") {
      assert = true;
      direction = "high";
#ifdef SEL_LOGGER_USE_DMTF_REGISTRY
      redfishMessageID += ".ReadingAboveUpperCriticalThreshold";
#else
      redfishMessageID += ".SensorThresholdCriticalHighGoingHigh";
#endif
    } else if (signalName == "CriticalHighAlarmDeasserted") {
      direction = "low";
#ifdef SEL_LOGGER_USE_DMTF_REGISTRY
      if (isOutsideNormalRange(conn, msg.get_sender(), msg.get_path())) {
        redfishMessageID += ".ReadingBelowUpperCriticalThreshold";
      } else {
        redfishMessageID += ".SensorReadingNormalRange";
      }
#else
      redfishMessageID += ".SensorThresholdCriticalHighGoingLow";
#endif
    }
  }
#ifdef SEL_LOGGER_USE_DMTF_REGISTRY
  else if (signalName == "HardShutdownLowAlarmAsserted" ||
           signalName == "HardShutdownLowAlarmDeasserted") {
    event = "HardShutdownLow";
    thresholdInterface = "xyz.openbmc_project.Sensor.Threshold.HardShutdown";
    // IPMI has no fatal offset; use the nearest lower-critical code
    eventData[0] =
        static_cast<uint8_t>(thresholdEventOffsets::lowerCritGoingLow);
    threshold = "hard shutdown low";
    if (signalName == "HardShutdownLowAlarmAsserted") {
      assert = true;
      direction = "low";
      redfishMessageID += ".ReadingBelowLowerFatalThreshold";
    } else if (signalName == "HardShutdownLowAlarmDeasserted") {
      direction = "high";
      if (isOutsideNormalRange(conn, msg.get_sender(), msg.get_path())) {
        redfishMessageID += ".ReadingAboveLowerFatalThreshold";
      } else {
        redfishMessageID += ".SensorReadingNormalRange";
      }
    }
  } else if (signalName == "HardShutdownHighAlarmAsserted" ||
             signalName == "HardShutdownHighAlarmDeasserted") {
    event = "HardShutdownHigh";
    thresholdInterface = "xyz.openbmc_project.Sensor.Threshold.HardShutdown";
    // IPMI has no fatal offset; use the nearest upper-critical code
    eventData[0] =
        static_cast<uint8_t>(thresholdEventOffsets::upperCritGoingHigh);
    threshold = "hard shutdown high";
    if (signalName == "HardShutdownHighAlarmAsserted") {
      assert = true;
      direction = "high";
      redfishMessageID += ".ReadingAboveUpperFatalThreshold";
    } else if (signalName == "HardShutdownHighAlarmDeasserted") {
      direction = "low";
      if (isOutsideNormalRange(conn, msg.get_sender(), msg.get_path())) {
        redfishMessageID += ".ReadingBelowUpperFatalThreshold";
      } else {
        redfishMessageID += ".SensorReadingNormalRange";
      }
    }
  }
#endif
  else {
    // Unsupported signal (e.g. HardShutdown under the OpenBMC registry, which
    // has no fatal message); skip logging.
    return;
  }
  // Indicate that bytes 2 and 3 are threshold sensor trigger values
  eventData[0] |= thresholdEventDataTriggerReadingByte2 |
                  thresholdEventDataTriggerReadingByte3;

  // Get the sensor reading to put in the event data
  sdbusplus::message_t getSensorValue =
      conn->new_method_call(msg.get_sender(), msg.get_path(),
                            "org.freedesktop.DBus.Properties", "GetAll");
  getSensorValue.append("xyz.openbmc_project.Sensor.Value");
  boost::container::flat_map<std::string, std::variant<double, int64_t>>
      sensorValue;
  try {
    sdbusplus::message_t getSensorValueResp = conn->call(getSensorValue);
    getSensorValueResp.read(sensorValue);
  } catch (const sdbusplus::exception_t &) {
    std::cerr << "error getting sensor value from " << msg.get_path() << "\n";
    return;
  }
  double max = 0;
  auto findMax = sensorValue.find("MaxValue");
  if (findMax != sensorValue.end()) {
    max = std::visit(ipmi::VariantToDoubleVisitor(), findMax->second);
  }
  double min = 0;
  auto findMin = sensorValue.find("MinValue");
  if (findMin != sensorValue.end()) {
    min = std::visit(ipmi::VariantToDoubleVisitor(), findMin->second);
  }

  try {
    eventData[1] = ipmi::getScaledIPMIValue(assertValue, max, min);
  } catch (const std::exception &e) {
    std::cerr << e.what();
    eventData[1] = selEvtDataUnspecified;
  }

  // Get the threshold value to put in the event data
  sdbusplus::message_t getThreshold =
      conn->new_method_call(msg.get_sender(), msg.get_path(),
                            "org.freedesktop.DBus.Properties", "Get");
  getThreshold.append(thresholdInterface, event);
  std::variant<double, int64_t> thresholdValue;
  try {
    sdbusplus::message_t getThresholdResp = conn->call(getThreshold);
    getThresholdResp.read(thresholdValue);
  } catch (const sdbusplus::exception_t &) {
    std::cerr << "error getting sensor threshold from " << msg.get_path()
              << "\n";
    return;
  }
  double thresholdVal =
      std::visit(ipmi::VariantToDoubleVisitor(), thresholdValue);

  double scale = 0;
  auto findScale = sensorValue.find("Scale");
  if (findScale != sensorValue.end()) {
    scale = std::visit(ipmi::VariantToDoubleVisitor(), findScale->second);
    thresholdVal *= std::pow(10, scale);
  }
  try {
    eventData[2] = ipmi::getScaledIPMIValue(thresholdVal, max, min);
  } catch (const std::exception &e) {
    std::cerr << e.what();
    eventData[2] = selEvtDataUnspecified;
  }

  std::string_view sensorName(msg.get_path());
  sensorName.remove_prefix(
      std::min(sensorName.find_last_of("/") + 1, sensorName.size()));

  std::string journalMsg(std::string(sensorName) + " sensor crossed a " +
                         threshold + " threshold going " + direction +
                         ". Reading=" + std::to_string(assertValue) +
                         " Threshold=" + std::to_string(thresholdVal) + ".");

#ifdef SEL_LOGGER_USE_DMTF_REGISTRY
  // DMTF SensorEvent messages take the sensor unit as an argument, so fetch it
  // and strip the "xyz.openbmc_project.Sensor.Value.Unit." prefix. Needed on
  // both the logging-service and journal paths. nullopt if it could not be
  // determined.
  std::optional<std::string> unit;
  sdbusplus::message_t getSensorUnit =
      conn->new_method_call(msg.get_sender(), msg.get_path(),
                            "org.freedesktop.DBus.Properties", "Get");
  getSensorUnit.append("xyz.openbmc_project.Sensor.Value", "Unit");
  try {
    std::variant<std::string> sensorUnit;
    conn->call(getSensorUnit).read(sensorUnit);
    std::string sensorUnitStr = std::get<std::string>(sensorUnit);
    std::string unitPrefix("xyz.openbmc_project.Sensor.Value.Unit.");
    if (sensorUnitStr.starts_with(unitPrefix)) {
      sensorUnitStr.erase(0, unitPrefix.length());
      unit = sensorUnitStr;
    } else {
      std::cerr << "Unexpected sensor unit format: " << sensorUnitStr << "\n";
    }
  } catch (const sdbusplus::exception_t &) {
    std::cerr << "Error getting sensor unit from " << msg.get_path() << "\n";
  }
  // Value used for the unit argument (and event-log text) when the sensor's
  // unit could not be determined.
  std::string unitStr = unit.value_or("Unknown Unit");
  // NormalRange has no threshold argument; every other message carries one.
  bool isNormalRange =
      (redfishMessageID == "SensorEvent." + dmtfMessageRegistryVersion +
                               ".SensorReadingNormalRange");
#endif

#ifdef SEL_LOGGER_SEND_TO_LOGGING_SERVICE
#ifdef SEL_LOGGER_USE_DMTF_REGISTRY
  std::string redfishMessage = "";
  if (!isNormalRange) {
    // <sensorName>,<sensorReading>,<sensorUnit>,<sensorThreshold>
    redfishMessage = std::format("{},{},{},{}", std::string(sensorName),
                                 std::to_string(assertValue), unitStr,
                                 std::to_string(thresholdVal));
  } else {
    // <sensorName>,<sensorReading>,<sensorUnit>
    redfishMessage = std::format("{},{},{}", std::string(sensorName),
                                 std::to_string(assertValue), unitStr);
  }
#else
  std::string redfishMessage = sensorName.data();
  redfishMessage = redfishMessage + "," + std::to_string(assertValue) + "," +
                   std::to_string(thresholdVal);
#endif
  selAddSystemRecord(redfishMessageID, redfishMessage,
                     std::string(msg.get_path()), eventData, assert,
                     selBMCGenID);
#else
#ifdef SEL_LOGGER_USE_DMTF_REGISTRY
  if (!isNormalRange) {
    selAddSystemRecord(conn, journalMsg, std::string(msg.get_path()), eventData,
                       assert, selBMCGenID, "REDFISH_MESSAGE_ID=%s",
                       redfishMessageID.c_str(),
                       "REDFISH_MESSAGE_ARGS=%.*s,%f,%s,%f",
                       static_cast<int>(sensorName.length()), sensorName.data(),
                       assertValue, unitStr.c_str(), thresholdVal);
  } else {
    selAddSystemRecord(conn, journalMsg, std::string(msg.get_path()), eventData,
                       assert, selBMCGenID, "REDFISH_MESSAGE_ID=%s",
                       redfishMessageID.c_str(),
                       "REDFISH_MESSAGE_ARGS=%.*s,%f,%s",
                       static_cast<int>(sensorName.length()), sensorName.data(),
                       assertValue, unitStr.c_str());
  }
#else
  selAddSystemRecord(
      conn, journalMsg, std::string(msg.get_path()), eventData, assert,
      selBMCGenID, "REDFISH_MESSAGE_ID=%s", redfishMessageID.c_str(),
      "REDFISH_MESSAGE_ARGS=%.*s,%f,%f", static_cast<int>(sensorName.length()),
      sensorName.data(), assertValue, thresholdVal);
#endif
#endif
}

inline static void
startThresholdAlarmMonitor(std::shared_ptr<sdbusplus::asio::connection> conn) {
  for (auto iter = matchers.begin(); iter != matchers.end(); iter++) {
    iter->second = std::make_shared<sdbusplus::bus::match_t>(
        static_cast<sdbusplus::bus_t &>(*conn),
        "type='signal',member=" + iter->first,
        [conn, iter](sdbusplus::message_t &msg) {
          generateEvent(iter->first, conn, msg);
        });
  }
}
