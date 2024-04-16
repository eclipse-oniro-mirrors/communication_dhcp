/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "dhcp_address_pool.h"
#include <map>
#include <securec.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "address_utils.h"
#include "common_util.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpServerAddressPool");

#define DHCP_POOL_INIT_SIZE 10
#define DHCP_RELEASE_REMOVE_MODE 0

static int g_releaseRemoveMode = DHCP_RELEASE_REMOVE_MODE;
static std::map<std::size_t, AddressBinding> g_bindingRecoders;
static int g_distributeMode = 0;

#define HASH_DEFAULT_VALUE 5381
#define HASH_CAL_CODE_CAL 5
//Write a HASH FUNCTION FOR uint8_t macAddr[DHCP_HWADDR_LENGTH]
std::size_t macAddrHash(uint8_t macAddr[DHCP_HWADDR_LENGTH])
{
    std::size_t hash = HASH_DEFAULT_VALUE;
    for (std::size_t i = 0; i < DHCP_HWADDR_LENGTH; ++i) {
        hash = ((hash << HASH_CAL_CODE_CAL) + hash) ^ static_cast<std::size_t>(macAddr[i]);
    }
    return hash;
}


AddressBinding *GetBindingByMac(uint8_t macAddr[DHCP_HWADDR_LENGTH])
{
    std::size_t hash = macAddrHash(macAddr);
    if (g_bindingRecoders.count(hash) > 0) {
        return &g_bindingRecoders[hash];
    }
    return nullptr;
}

AddressBinding *QueryBinding(uint8_t macAddr[DHCP_HWADDR_LENGTH], PDhcpOptionList cliOptins)
{
    return GetBindingByMac(macAddr);
}

AddressBinding *AddNewBinding(uint8_t macAddr[DHCP_HWADDR_LENGTH], PDhcpOptionList cliOptins)
{
    AddressBinding newBind = {0};
    newBind.bindingMode = BIND_MODE_DYNAMIC;
    newBind.bindingStatus = BIND_PENDING;
    if (memcpy_s(newBind.chaddr, DHCP_HWADDR_LENGTH, macAddr, DHCP_HWADDR_LENGTH) != EOK) {
        return nullptr;
    }
    newBind.bindingTime = Tmspsec();
    newBind.pendingTime = Tmspsec();
    newBind.expireIn = newBind.bindingTime + DHCP_LEASE_TIME;
    newBind.leaseTime = DHCP_LEASE_TIME;
    g_bindingRecoders[macAddrHash(macAddr)] = newBind;
    return GetBindingByMac(macAddr);
}

int CheckIpAvailability(DhcpAddressPool *pool, uint8_t macAddr[DHCP_HWADDR_LENGTH], uint32_t distIp)
{
    if (!pool) {
        DHCP_LOGE("pool pointer is null.");
        return DHCP_FALSE;
    }
    if (IsReserved(macAddr)) {
        DHCP_LOGW("client address(%s) is reserved address.", ParseLogMac(macAddr));
        return DHCP_FALSE;
    }
    AddressBinding *lease = GetLease(pool, distIp);
    if (lease) {
        int same = AddrEquels(lease->chaddr, macAddr, MAC_ADDR_LENGTH);
        if (distIp == pool->serverId || distIp == pool->gateway) {
            return DHCP_FALSE;
        }
        if (lease->bindingMode == BIND_MODE_STATIC && !same) {
            return DHCP_FALSE;
        }
        if (IsReservedIp(pool, distIp) && !same) {
            return DHCP_FALSE;
        }
        if (same) {
            lease->pendingTime = Tmspsec();
            lease->bindingTime = lease->pendingTime;
            return DHCP_TRUE;
        }
        if (IsExpire(lease)) {
            DHCP_LOGD("the binding recoder has expired.");
            lease->pendingTime = Tmspsec();
            lease->bindingTime = lease->pendingTime;
            RemoveBinding(lease->chaddr);
            if (memcpy_s(lease->chaddr, DHCP_HWADDR_LENGTH, macAddr, MAC_ADDR_LENGTH) != EOK) {
                DHCP_LOGD("failed to rewrite client address.");
            }
            return DHCP_TRUE;
        }
        return DHCP_FALSE;
    }
    return DHCP_TRUE;
}

int CheckRangeAvailability(
    DhcpAddressPool *pool, uint8_t macAddr[DHCP_HWADDR_LENGTH], uint32_t distIp, int *outOfRange)
{
    if (!pool || !pool->addressRange.beginAddress || !pool->addressRange.endAddress) {
        return RET_ERROR;
    }
    if (!pool->netmask || IsEmptyHWAddr(macAddr)) {
        return RET_ERROR;
    }
    uint32_t beginIp = pool->addressRange.beginAddress;
    uint32_t endIp = pool->addressRange.endAddress;
    if (IpInRange(distIp, beginIp, endIp, pool->netmask)) {
        DHCP_LOGD("distribution IP address");
        AddressBinding lease = {0};
        lease.pendingTime = Tmspsec();
        lease.bindingMode = BIND_PENDING;
        lease.ipAddress = distIp;
        lease.bindingTime = lease.pendingTime;
        lease.leaseTime = pool->leaseTime;
        if (memcpy_s(lease.chaddr, sizeof(lease.chaddr), macAddr, MAC_ADDR_LENGTH) != EOK) {
            DHCP_LOGE("failed to set lease chaddr fields");
            return RET_ERROR;
        }
        if (AddLease(pool, &lease) != RET_SUCCESS) {
            DHCP_LOGE("failed to add lease.");
            return RET_ERROR;
        }
        return RET_SUCCESS;
    }
    if (*outOfRange) {
        DHCP_LOGD("address is out of range");
        return RET_FAILED;
    } else {
        *outOfRange = 1;
    }
    return RET_FAILED;
}

uint32_t NextIpOffset(uint32_t netmask)
{
    uint32_t offset = 0;
    if (g_distributeMode && netmask) {
        uint32_t total = HostTotal(netmask);
        if (total) {
            offset = Tmspusec() % total;
        }
        DHCP_LOGD("next ip offset is: %u", offset);
    }
    return offset;
}

uint32_t AddressDistribute(DhcpAddressPool *pool, uint8_t macAddr[DHCP_HWADDR_LENGTH])
{
    if (!pool || !pool->addressRange.beginAddress || !pool->addressRange.endAddress) {
        return 0;
    }
    if (!pool->netmask || IsEmptyHWAddr(macAddr)) {
        return 0;
    }
    if (pool->distribution == 0) {
        pool->distribution = pool->addressRange.beginAddress;
    }
    uint32_t total = HostTotal(pool->netmask);
    uint32_t distIp = pool->distribution;
    if (!distIp || distIp < pool->addressRange.beginAddress) {
        distIp = pool->addressRange.beginAddress;
    }
    int distSucess = 0;
    int outOfRange = 0;
    for (uint32_t i = 0; i < total; i++) {
        int offset = 0;
        if (i == 0) {
            offset = NextIpOffset(pool->netmask);
        }
        distIp = NextIpAddress(distIp, pool->netmask, offset);
        if (!CheckIpAvailability(pool, macAddr, distIp)) {
            continue;
        }
        int ret = CheckRangeAvailability(pool, macAddr, distIp, &outOfRange);
        if (ret == RET_ERROR) {
            break;
        }
        if (ret == RET_SUCCESS) {
            distSucess = 1;
            break;
        }
    }
    if (!distSucess || !distIp) {
        return 0;
    }
    pool->distribution = distIp;
    return pool->distribution;
}

int InitAddressPool(DhcpAddressPool *pool, const char *ifname, PDhcpOptionList options)
{
    if (!pool) {
        DHCP_LOGD("address pool pointer is null.");
        return RET_ERROR;
    }
    if (memset_s(pool, sizeof(DhcpAddressPool), 0, sizeof(DhcpAddressPool)) != EOK) {
        DHCP_LOGD("failed to init dhcp pool.");
        return RET_ERROR;
    }
    if (memset_s(pool->ifname, IFACE_NAME_SIZE, '\0', IFACE_NAME_SIZE) != EOK) {
        DHCP_LOGD("failed to reset interface name.");
        return RET_ERROR;
    }
    if (strncpy_s(pool->ifname, IFACE_NAME_SIZE, ifname, strlen(ifname)) != EOK) {
        DHCP_LOGD("failed to set interface name.");
        return RET_ERROR;
    }
    if (InitOptionList(&pool->fixedOptions) != RET_SUCCESS) {
        DHCP_LOGD("failed to init options field for dhcp pool.");
        return RET_FAILED;
    }
    g_bindingRecoders.clear();

    pool->distribue = AddressDistribute;
    pool->binding = QueryBinding;
    pool->newBinding = AddNewBinding;
    pool->leaseTable.clear();
    return RET_SUCCESS;
}

void FreeAddressPool(DhcpAddressPool *pool)
{
    if (!pool) {
        return;
    }

    if (pool->fixedOptions.size > 0) {
        ClearOptions(&pool->fixedOptions);
    }

    if (pool) {
        pool->leaseTable.clear();
    }

    if (pool && HasInitialized(&pool->fixedOptions)) {
        FreeOptionList(&pool->fixedOptions);
    }
}

AddressBinding *FindBindingByIp(uint32_t ipAddress)
{
    if (g_bindingRecoders.empty()) {
        return nullptr;
    }
    for (auto current: g_bindingRecoders) {
        AddressBinding *binding = &current.second;
        if (binding && ipAddress == binding->ipAddress) {
            return binding;
        }
    }
    return nullptr;
}

int IsReserved(uint8_t macAddr[DHCP_HWADDR_LENGTH])
{
    if (g_bindingRecoders.count(macAddrHash(macAddr)) > 0) {
        AddressBinding *binding = &g_bindingRecoders[macAddrHash(macAddr)];
        if (binding && binding->bindingMode == BIND_MODE_RESERVED) {
            return DHCP_TRUE;
        }
    }
    return DHCP_FALSE;
}

int IsReservedIp(DhcpAddressPool *pool, uint32_t ipAddress)
{
    if (!pool) {
        return DHCP_FALSE;
    }
    if (!ipAddress) {
        return DHCP_FALSE;
    }
    if (pool->leaseTable.count(ipAddress) >0) {
        AddressBinding *lease = &pool->leaseTable[ipAddress];
        if (lease && lease->bindingMode == BIND_MODE_RESERVED) {
            return DHCP_TRUE;
        }
    }
    return DHCP_FALSE;
}

int AddBinding(AddressBinding *binding)
{
    if (!binding) {
        DHCP_LOGE("binding pointer is null.");
        return RET_ERROR;
    }
    if (IsEmptyHWAddr(binding->chaddr)) {
        DHCP_LOGE("binding address is empty.");
        return RET_ERROR;
    }
    if (!binding->ipAddress) {
        DHCP_LOGE("binding ip is empty.");
        return RET_ERROR;
    }
    if (g_bindingRecoders.count(macAddrHash(binding->chaddr)) > 0) {
        DHCP_LOGW("binding recoder exist.");
        return RET_FAILED;
    }
    g_bindingRecoders[macAddrHash(binding->chaddr)] = *binding;
    return RET_SUCCESS;
}

int AddReservedBinding(uint8_t macAddr[DHCP_HWADDR_LENGTH])
{
    AddressBinding *binding = GetBindingByMac(macAddr);
    if (binding) {
        binding->bindingMode = BIND_MODE_RESERVED;
    } else {
        AddressBinding bind = {0};
        bind.bindingMode = BIND_MODE_RESERVED;
        bind.bindingTime = Tmspsec();
        bind.pendingTime = bind.bindingTime;
        g_bindingRecoders[macAddrHash(macAddr)] = bind;
    }
    return RET_SUCCESS;
}

int RemoveBinding(uint8_t macAddr[DHCP_HWADDR_LENGTH])
{
    if (g_bindingRecoders.count(macAddrHash(macAddr)) > 0) {
        g_bindingRecoders.erase(macAddrHash(macAddr));
        return RET_SUCCESS;
    }
    return RET_FAILED;
}

int RemoveReservedBinding(uint8_t macAddr[DHCP_HWADDR_LENGTH])
{
    if (g_bindingRecoders.count(macAddrHash(macAddr)) > 0) {
        AddressBinding *binding = &g_bindingRecoders[macAddrHash(macAddr)];
        if (binding && binding->bindingMode == BIND_MODE_RESERVED) {
            g_bindingRecoders.erase(macAddrHash(macAddr));
            return RET_SUCCESS;
        }
    }
    DHCP_LOGW("binding mode is not 'BIND_MODE_RESERVED'.");
    return RET_FAILED;
}

int ReleaseBinding(uint8_t macAddr[DHCP_HWADDR_LENGTH])
{
    if (g_bindingRecoders.count(macAddrHash(macAddr)) > 0) {
        if (g_releaseRemoveMode) {
            g_bindingRecoders.erase(macAddrHash(macAddr));
            return RET_SUCCESS;
        }
        AddressBinding *binding = &g_bindingRecoders[macAddrHash(macAddr)];
        if (binding) {
            binding->bindingStatus = BIND_RELEASED;
            return RET_SUCCESS;
        }
    }
    return RET_FAILED;
}

int AddLease(DhcpAddressPool *pool, AddressBinding *lease)
{
    if (!pool) {
        return RET_ERROR;
    }

    if (!lease || !lease->ipAddress || IsEmptyHWAddr(lease->chaddr)) {
        return RET_ERROR;
    }

    if (pool->leaseTable.count(lease->ipAddress) > 0) {
        DHCP_LOGD("update lease info.");
        pool->leaseTable[lease->ipAddress] = *lease;
        return RET_SUCCESS;
    } else {
        DHCP_LOGD("insert lease info.");
        pool->leaseTable[lease->ipAddress] = *lease;
        return RET_SUCCESS;
    }
}

AddressBinding *GetLease(DhcpAddressPool *pool, uint32_t ipAddress)
{
    if (!ipAddress) {
        return nullptr;
    }
    if (!pool) {
        return nullptr;
    }
    int ipAddr = ipAddress;
    if (pool->leaseTable.count(ipAddr) > 0) {
        return &pool->leaseTable[ipAddr];
    }
    return nullptr;
}

int UpdateLease(DhcpAddressPool *pool, AddressBinding *lease)
{
    if (!pool) {
        return RET_ERROR;
    }

    if (!lease || !lease->ipAddress || IsEmptyHWAddr(lease->chaddr)) {
        return RET_ERROR;
    }
    if (pool->leaseTable.count(lease->ipAddress) > 0) {
        pool->leaseTable[lease->ipAddress] = *lease;
        return RET_SUCCESS;
    }
    return RET_FAILED;
}

int RemoveLease(DhcpAddressPool *pool, AddressBinding *lease)
{
    if (!pool) {
        return RET_ERROR;
    }

    if (!lease || !lease->ipAddress || IsEmptyHWAddr(lease->chaddr)) {
        return RET_ERROR;
    }

    if (pool->leaseTable.count(lease->ipAddress) > 0) {
        pool->leaseTable.erase(lease->ipAddress);
        return RET_SUCCESS;
    }
    return RET_FAILED;
}

int LoadBindingRecoders(DhcpAddressPool *pool)
{
    if (pool == nullptr) {
        return RET_FAILED;
    }
    char filePath[DHCP_LEASE_FILE_LENGTH] = {0};
    if (snprintf_s(filePath, sizeof(filePath), sizeof(filePath) - 1, "%s.%s", DHCPD_LEASE_FILE, pool->ifname) < 0) {
        DHCP_LOGE("Failed to get dhcp lease file path!");
        return RET_FAILED;
    }
    FILE *fp = fopen(filePath, "r");
    if (fp == nullptr) {
        return RET_FAILED;
    }
    uint32_t beginIp = pool->addressRange.beginAddress;
    uint32_t endIp = pool->addressRange.endAddress;
    uint32_t netmask = pool->netmask;
    char line[DHCP_FILE_LINE_LENGTH] = {0};
    while (fgets(line, DHCP_FILE_LINE_LENGTH, fp) != nullptr) {
        TrimString(line);
        if (line[0] == '\0') { /* skip empty line */
            continue;
        }
        AddressBinding bind = {0};
        if (ParseAddressBinding(&bind, line) != 0) {
            continue;
        }
        if (IpInRange(bind.ipAddress, beginIp, endIp, netmask)) {
            pool->leaseTable[bind.ipAddress] = bind;
        }
    }

    if (fclose(fp) != 0) {
        DHCP_LOGE("LoadBindingRecoders fclose fp failed!");
    }
    return RET_SUCCESS;
}

int SaveBindingRecoders(const DhcpAddressPool *pool, int force)
{
    if (pool == nullptr) {
        DHCP_LOGE("Save binding record, pool is null");
        return RET_FAILED;
    }
    static uint64_t lastTime = 0;
    uint64_t currTime = Tmspsec();
    if (force == 0 && currTime < lastTime + DHCP_REFRESH_LEASE_FILE_INTERVAL) {
        DHCP_LOGE("Save binding record, time interval is not satisfied.");
        return RET_WAIT_SAVE;
    }
    char filePath[DHCP_LEASE_FILE_LENGTH] = {0};
    if (snprintf_s(filePath, sizeof(filePath), sizeof(filePath) - 1, "%s.%s", DHCPD_LEASE_FILE, pool->ifname) < 0) {
        DHCP_LOGE("Failed to set dhcp lease file path!");
        return RET_FAILED;
    }
    char line[DHCP_FILE_LINE_LENGTH] = {0};
    FILE *fp = fopen(filePath, "w");
    if (fp == nullptr) {
        DHCP_LOGE("Save binding records %{private}s failed: %{public}d", filePath, errno);
        return RET_FAILED;
    }
    for (auto index: pool->leaseTable) {
        AddressBinding *binding = &index.second;
        if (binding && WriteAddressBinding(binding, line, sizeof(line)) != RET_SUCCESS) {
            DHCP_LOGE("Failed to convert binding info to string");
        } else {
            fprintf(fp, "%s\n", line);
        }
    }

    if (fclose(fp) != 0) {
        DHCP_LOGE("SaveBindingRecoders fclose fp failed!");
    }
    lastTime = currTime;
    return RET_SUCCESS;
}

void SetDistributeMode(int mode)
{
    g_distributeMode = mode;
}
int GetDistributeMode(void)
{
    return g_distributeMode;
}

int DeleteMacInLease(DhcpAddressPool *pool, AddressBinding *lease)
{
    if ((pool == nullptr) || (lease == nullptr)) {
        DHCP_LOGE("DeleteMacInLease pointer is null.");
        return RET_ERROR;
    }
    for (auto it = pool->leaseTable.begin(); it != pool->leaseTable.end();) {
        AddressBinding *binding = &(it->second);
        if (binding && AddrEquels(binding->chaddr, lease->chaddr, MAC_ADDR_LENGTH)) {
            it = pool->leaseTable.erase(it);
        } else {
            ++it;
        }
    }
    return RET_SUCCESS;
}
