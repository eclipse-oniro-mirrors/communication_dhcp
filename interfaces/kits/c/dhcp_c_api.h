/*
 * Copyright (C) 2020-2023 Huawei Device Co., Ltd.
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
#ifndef OHOS_DHCP_C_API_H
#define OHOS_DHCP_C_API_H

#include "dhcp_error_code.h"
#include "dhcp_result_event.h"

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * @Description : Obtain the dhcp result of specified interface asynchronously.
     *
     * @param ifname - interface name, eg:wlan0 [in]
     * @param pResultNotify - dhcp result notify [in]
     * @Return : success - DHCP_SUCCESS, failed - others.
     */
    DhcpErrorCode RegisterDhcpClientCallBack(const char *ifname, const ClientCallBack *event);
    /**
     * @Description : Start dhcp client service of specified interface.
     *
     * @param ifname - interface name, eg:wlan0 [in]
     * @param bIpv6 - can or not get ipv6 [in]
     * @Return : success - DHCP_SUCCESS, failed - others.
     */
    DhcpErrorCode StartDhcpClient(const char *ifname, bool bIpv6);
    /**
     * @Description : set bssid of specified interface.
     *
     * @param ifname - interface name, eg:wlan0 [in]
     * @param targetBssid - target Bssid [in]
     * @Return : success - DHCP_SUCCESS, failed - others.
     */
    DhcpErrorCode SetConfiguration(const char *ifname, const RouterConfig config);
    /**
     * @Description : Stop dhcp client service of specified interface.
     *
     * @param ifname - interface name, eg:wlan0 [in]
     * @param bIpv6 - can or not get ipv6 [in]
     * @Return : success - DHCP_SUCCESS, failed - others.
     */
    DhcpErrorCode StopDhcpClient(const char *ifname, bool bIpv6);
    /**
     * @Description : Renew dhcp client service of specified interface.
     *
     * @param ifname - interface name, eg:wlan0 [in]
     * @Return : success - DHCP_SUCCESS, failed - others.
     */
    DhcpErrorCode RenewDhcpClient(const char *ifname);

    DhcpErrorCode RegisterDhcpServerCallBack(const char *ifname, const ServerCallBack *event);
    DhcpErrorCode StartDhcpServer(const char *ifname);
    DhcpErrorCode StopDhcpServer(const char *ifname);
    DhcpErrorCode SetDhcpRange(const char *ifname, const DhcpRange *range);
    DhcpErrorCode SetDhcpName(const char *ifname, const char *tagName);
    DhcpErrorCode PutDhcpRange(const char *tagName, const DhcpRange *range);
    DhcpErrorCode RemoveAllDhcpRange(const char *tagName);
    DhcpErrorCode RemoveDhcpRange(const char *tagName, const void *range);
    DhcpErrorCode GetDhcpClientInfos(const char *ifname, int staNumber, DhcpStationInfo *staInfo, int *staSize);
    DhcpErrorCode UpdateLeasesTime(const char *leaseTime);
#ifdef __cplusplus
}
#endif
#endif