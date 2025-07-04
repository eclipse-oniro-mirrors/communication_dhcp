/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dhcpclient_fuzzer.h"
#include "dhcp_client.h"
#include "dhcp_event.h"

namespace OHOS {
namespace DHCP {
    std::shared_ptr<DhcpClient> dhcpClient = DhcpClient::GetInstance(DHCP_CLIENT_ABILITY_ID);
    static OHOS::sptr<DhcpClientCallBack> dhcpClientCallBack =
        OHOS::sptr<DhcpClientCallBack>(new (std::nothrow)DhcpClientCallBack());
    static OHOS::sptr<DhcpServerCallBack> dhcpServerCallBack =
        OHOS::sptr<DhcpServerCallBack>(new (std::nothrow)DhcpServerCallBack());
    bool DhcpClientFuzzerTest(const uint8_t* data, size_t size)
    {
        if (dhcpClient == nullptr) {
            return false;
        }

        RouterConfig config;
        config.ifname = std::string(reinterpret_cast<const char*>(data), size);
        config.bssid = std::string(reinterpret_cast<const char*>(data), size);
        config.bIpv6 = false;
        config.prohibitUseCacheIp = false;
        dhcpClient->StartDhcpClient(config);
        dhcpClient->StopDhcpClient(config.ifname, true, true);
        dhcpClient->RegisterDhcpClientCallBack(config.ifname, dhcpClientCallBack);
        IpCacheInfo ipCacheInfo;
        ipCacheInfo.ssid = std::string(reinterpret_cast<const char*>(data), size);
        ipCacheInfo.bssid = std::string(reinterpret_cast<const char*>(data), size);
        dhcpClient->DealWifiDhcpCache(WIFI_DHCP_CACHE_ADD, ipCacheInfo);
        dhcpClient->DealWifiDhcpCache(WIFI_DHCP_CACHE_REMOVE, ipCacheInfo);
        return true;
    }
}  // namespace DHCP
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DHCP::DhcpClientFuzzerTest(data, size);
    return 0;
}
