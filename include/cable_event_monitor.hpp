/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#pragma once
#include <sel_logger.hpp>
#include <sensorutils.hpp>
#include <string_view>
#include <variant>

enum class cableStatusEvent : uint8_t
{
    deassertedEvent = 0x01,
    assertedEvent = 0x00
};

static const std::string openBMCMessageRegistryVersionCable("0.1");
inline static sdbusplus::bus::match::match startCableAssertMonitor(
    std::shared_ptr<sdbusplus::asio::connection> conn)
{
    auto cableAssertMatcherCallback = [conn](sdbusplus::message::message&
                                                     msg) {
        // This static set of std::pair<path, event> tracks asserted events to
        // avoid duplicate logs or deasserts logged without an assert
        std::vector<uint8_t> eventData(selEvtDataMaxSize,
                                       selEvtDataUnspecified);
        // Get the event type and assertion details from the message
        std::string sensorName;
        std::string CableInterface;
        bool assert;
        bool cableStatus;
        try
        { 
            msg.read(sensorName, CableInterface, assert,cableStatus);    
        }
        catch (const sdbusplus::exception_t&)
        { 
            std::cerr << "error getting assert signal data from "
                      << msg.get_path() << "\n";
            return;
        }
        if (cableStatus)
        {
            eventData[0] =
                static_cast<uint8_t>(cableStatusEvent::assertedEvent);
        }
        else 
        {
           eventData[0] =
                static_cast<uint8_t>(cableStatusEvent::deassertedEvent);
        }
        eventData[1] = selEvtDataUnspecifiedDiscrete;
        eventData[2] = selEvtDataUnspecifiedDiscrete;
        std::string redfishMessageID =
            "OpenBMC." + openBMCMessageRegistryVersionCable;
         std::string statusString = "in error";
        if (cableStatus )
        {
           redfishMessageID += ".SensorCableStatusEnable";
           statusString = "enabled";
        }
        else 
        {
          redfishMessageID += ".SensorCableStatusError";
        }
    std::string journalMsg(std::string(sensorName) + " sensor is now "+ statusString);

    #ifdef SEL_LOGGER_SEND_TO_LOGGING_SERVICE
        std::string redfishMessage = sensorName.data();
            selAddSystemRecord(redfishMessageID, redfishMessage,
                            std::string(msg.get_path()), eventData, assert,
                            selBMCGenID);
    #else
        selAddSystemRecord(
            journalMsg, std::string(msg.get_path()), eventData, assert,
            selBMCGenID, "REDFISH_MESSAGE_ID=%s", redfishMessageID.c_str(),
            "REDFISH_MESSAGE_ARGS=%.*s", sensorName.length(),
            sensorName.data());
    #endif
    };
    sdbusplus::bus::match::match cableAssertMatcher(
        static_cast<sdbusplus::bus::bus&>(*conn),
        "type='signal', member='CableStatus'",
        std::move(cableAssertMatcherCallback));
    return cableAssertMatcher;
}
