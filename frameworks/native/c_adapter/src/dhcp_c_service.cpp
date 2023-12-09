/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
#include "../../../interfaces/kits/c/dhcp_c_api.h"
#include "../../../interfaces/inner_api/dhcp_client.h"
#include "../../../interfaces/inner_api/dhcp_server.h"
#include "../../include/dhcp_sdk_define.h"
#include "../inc/dhcp_c_utils.h"
#include "../../include/dhcp_event.h"
#include "dhcp_logger.h"
#ifndef OHOS_ARCH_LITE
#include <string_ex.h>
#endif
DEFINE_DHCPLOG_DHCP_LABEL("DhcpCService");
std::shared_ptr<OHOS::Wifi::DhcpClient> dhcpClientPtr = OHOS::Wifi::DhcpClient::GetInstance(DHCP_CLIENT_ABILITY_ID);
std::shared_ptr<OHOS::Wifi::DhcpServer> dhcpServerPtr = OHOS::Wifi::DhcpServer::GetInstance(DHCP_SERVER_ABILITY_ID);

#ifdef OHOS_ARCH_LITE
    static std::shared_ptr<DhcpClientCallBack> dhcpClientCallBack =
        std::shared_ptr<DhcpClientCallBack>(new (std::nothrow)DhcpClientCallBack());
    static std::shared_ptr<DhcpServerCallBack> dhcpServerCallBack =
        std::shared_ptr<DhcpServerCallBack>(new (std::nothrow)DhcpServerCallBack());
#else
    static OHOS::sptr<DhcpClientCallBack> dhcpClientCallBack =
        OHOS::sptr<DhcpClientCallBack>(new (std::nothrow)DhcpClientCallBack());
    static OHOS::sptr<DhcpServerCallBack> dhcpServerCallBack =
        OHOS::sptr<DhcpServerCallBack>(new (std::nothrow)DhcpServerCallBack());
#endif

NO_SANITIZE("cfi")  DhcpErrorCode RegisterDhcpClientCallBack(const char *ifname, const ClientCallBack *event)
{
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(event, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpClientPtr, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpClientCallBack, DHCP_INVALID_PARAM);
    dhcpClientCallBack->RegisterCallBack(ifname, event);
    return GetCErrorCode(dhcpClientPtr->RegisterDhcpClientCallBack(ifname, dhcpClientCallBack));
}

NO_SANITIZE("cfi") DhcpErrorCode StartDhcpClient(const char *ifname, bool bIpv6)
{
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpClientPtr, DHCP_INVALID_PARAM);
    return GetCErrorCode(dhcpClientPtr->StartDhcpClient(ifname, bIpv6));
}

NO_SANITIZE("cfi") DhcpErrorCode StopDhcpClient(const char *ifname, bool bIpv6)
{
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpClientPtr, DHCP_INVALID_PARAM);
    return  GetCErrorCode(dhcpClientPtr->StopDhcpClient(ifname, bIpv6));
}

NO_SANITIZE("cfi") DhcpErrorCode RenewDhcpClient(const char *ifname)
{
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpClientPtr, DHCP_INVALID_PARAM);
    return GetCErrorCode(dhcpClientPtr->RenewDhcpClient(ifname));
}

NO_SANITIZE("cfi") DhcpErrorCode RegisterDhcpServerCallBack(const char *ifname, const ServerCallBack *event)
{
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(event, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerCallBack, DHCP_INVALID_PARAM);
    dhcpServerCallBack->RegisterCallBack(ifname, event);
    return GetCErrorCode(dhcpServerPtr->RegisterDhcpServerCallBack(ifname, dhcpServerCallBack));
}

NO_SANITIZE("cfi") DhcpErrorCode StartDhcpServer(const char *ifname)
{
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
    return GetCErrorCode(dhcpServerPtr->StartDhcpServer(ifname));
}

NO_SANITIZE("cfi") DhcpErrorCode StopDhcpServer(const char *ifname)
{
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
    return GetCErrorCode(dhcpServerPtr->StopDhcpServer(ifname));
}

NO_SANITIZE("cfi") DhcpErrorCode SetDhcpRange(const char *ifname, const DhcpRange *range)
{
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(range, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
    OHOS::Wifi::DhcpRange rangeNew;
    rangeNew.iptype = range->iptype;
    rangeNew.strStartip = range->strStartip;
    rangeNew.strEndip = range->strEndip;
    rangeNew.strSubnet = range->strSubnet;
    rangeNew.strTagName = range->strTagName;
    return GetCErrorCode(dhcpServerPtr->SetDhcpRange(ifname, rangeNew));
}

NO_SANITIZE("cfi") DhcpErrorCode SetDhcpName(const char *ifname, const char *tagName)
{
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(tagName, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
    return GetCErrorCode(dhcpServerPtr->SetDhcpName(ifname, tagName));
}

NO_SANITIZE("cfi") DhcpErrorCode PutDhcpRange(const char *tagName, const DhcpRange *range)
{
    CHECK_PTR_RETURN(tagName, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(range, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
    OHOS::Wifi::DhcpRange rangeNew;
    rangeNew.iptype = range->iptype;
    rangeNew.strStartip = range->strStartip;
    rangeNew.strEndip = range->strEndip;
    rangeNew.strSubnet = range->strSubnet;
    rangeNew.strTagName = range->strTagName;
    return GetCErrorCode(dhcpServerPtr->PutDhcpRange(tagName, rangeNew));
}

NO_SANITIZE("cfi") DhcpErrorCode RemoveAllDhcpRange(const char *tagName)
{
    CHECK_PTR_RETURN(tagName, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
    return GetCErrorCode(dhcpServerPtr->RemoveAllDhcpRange(tagName));
}

DhcpErrorCode RemoveDhcpRange(const char *tagName, const void *range)
{
    CHECK_PTR_RETURN(tagName, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(range, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
    return GetCErrorCode(dhcpServerPtr->RemoveDhcpRange(tagName, *(OHOS::Wifi::DhcpRange *)range));
}

DhcpErrorCode GetDhcpClientInfos(const char *ifname, int staNumber, DhcpStationInfo *staInfo, int *staSize)
{
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
    std::vector<std::string> vecInfo;
    DhcpErrorCode ret = GetCErrorCode(dhcpServerPtr->GetDhcpClientInfos(ifname, vecInfo));
    if (ret != DHCP_SUCCESS) {
        DHCP_LOGE("GetDhcpClientInfos failed!");
        return DHCP_FAILED;
    }
    int size = (int)vecInfo.size();
    DHCP_LOGI("GetDhcpClientInfos size: %{public}d", size);
    int i;
    for (i = 0; i < size; i++) {
        std::vector<std::string> tmp;
        std::string str = vecInfo[i];
        OHOS::SplitStr(str, " ", tmp);
        if (tmp.empty()) {
            continue;
        }
        if (tmp[0] == "duid") {
            break;
        }
        if (tmp.size() < DHCP_LEASE_FORMAT_SIZE) {
            continue;
        }
        std::string mac = tmp[DHCP_LEASE_MAC_ADDR_POS];
        std::string ipAddr = tmp[DHCP_LEASE_IP_ADDR_POS];
        std::string deviceName = tmp[DHCP_LEASE_HOSTNAME_POS];
        DHCP_LOGI("GetDhcpClientInfos mac:%{public}s", mac.c_str());

        if (i >= staNumber) {
            break;
        }
        
        if (strcpy_s(staInfo[i].macAddr, MAC_ADDR_MAX_LEN, mac.c_str()) != EOK) {
            DHCP_LOGE("get dhcp client info, cpy mac failed! srclen=%{public}zu", strlen(mac.c_str()));
            return DHCP_FAILED;
        }
        if (strcpy_s(staInfo[i].ipAddr, INET_ADDRSTRLEN, ipAddr.c_str()) != EOK) {
            DHCP_LOGE("get dhcp client info, cpy ip failed!");
            return DHCP_FAILED;
        }
        if (strcpy_s(staInfo[i].deviceName, DHCP_LEASE_DATA_MAX_LEN, deviceName.c_str()) != EOK) {
            DHCP_LOGE("get dhcp client info, cpy name failed!");
            return DHCP_FAILED;
        }
    }
    *staSize = i;
    
    DHCP_LOGI("GetDhcpClientInfos3 %{public}d macAddr:%{public}s", i, staInfo[0].macAddr);

    return DHCP_SUCCESS;
}

NO_SANITIZE("cfi") DhcpErrorCode UpdateLeasesTime(const char *leaseTime)
{
    CHECK_PTR_RETURN(leaseTime, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
    return GetCErrorCode(dhcpServerPtr->UpdateLeasesTime(leaseTime));
}