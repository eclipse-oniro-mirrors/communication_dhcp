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
#include "dhcp_client_impl.h"
#include "i_dhcp_client.h"
#include "dhcp_client_proxy.h"
#ifndef OHOS_ARCH_LITE
#include "dhcp_sa_manager.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#endif
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpClientImpl");

namespace OHOS {
namespace DHCP {
#define RETURN_IF_FAIL(cond)                          \
    do {                                              \
        if (!(cond)) {                                \
            DHCP_LOGI("'%{public}s' failed.", #cond); \
            return DHCP_E_FAILED;                     \
        }                                             \
    } while (0)

DhcpClientImpl::DhcpClientImpl() : client_(nullptr)
{}

DhcpClientImpl::~DhcpClientImpl()
{
#ifdef OHOS_ARCH_LITE
    DhcpClientProxy::ReleaseInstance();
#endif
}

bool DhcpClientImpl::Init(int systemAbilityId)
{
     DHCP_LOGI("DhcpClientImpl enter Init!");
#ifdef OHOS_ARCH_LITE
    DhcpClientProxy *clientProxy = DhcpClientProxy::GetInstance();
    if (clientProxy == nullptr) {
        DHCP_LOGE("get dhcp client proxy failed.");
        return false;
    }
    if (clientProxy->Init() != DHCP_OPT_SUCCESS) {
        DHCP_LOGE("dhcp client proxy init failed.");
        DhcpClientProxy::ReleaseInstance();
        return false;
    }
    client_ = clientProxy;
    return true;
#else
    systemAbilityId_ = systemAbilityId;
    return true;
#endif
}

bool DhcpClientImpl::GetDhcpClientProxy()
{
#ifdef OHOS_ARCH_LITE
    return (client_ != nullptr);
#else
    DhcpSaLoadManager::GetInstance().LoadWifiSa(systemAbilityId_);
    if (IsRemoteDied() == false) {
        DHCP_LOGE("remote died false, %{public}d", systemAbilityId_);
        return true;
    }

    sptr<ISystemAbilityManager> sa_mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sa_mgr == nullptr) {
        DHCP_LOGE("failed to get SystemAbilityManager");
        return false;
    }

    sptr<IRemoteObject> object = sa_mgr->GetSystemAbility(systemAbilityId_);
    if (object == nullptr) {
        DHCP_LOGE("failed to get DEVICE_SERVICE");
        return false;
    }

    client_ = iface_cast<OHOS::DHCP::IDhcpClient>(object);
    if (client_ == nullptr) {
        DHCP_LOGI("DhcpClientImpl new DhcpClientProxy");
        client_ = new (std::nothrow)DhcpClientProxy(object);
    }

    if (client_ == nullptr) {
        DHCP_LOGE("dhcp client init failed. %{public}d", systemAbilityId_);
        return false;
    }
    return true;
#endif
}

bool DhcpClientImpl::IsRemoteDied(void)
{
    return (client_ == nullptr) ? true : client_->IsRemoteDied();
}

#ifdef OHOS_ARCH_LITE
ErrCode DhcpClientImpl::RegisterDhcpClientCallBack(const std::string& ifname,
    const std::shared_ptr<IDhcpClientCallBack> &callback)
#else
ErrCode DhcpClientImpl::RegisterDhcpClientCallBack(const std::string& ifname,
    const sptr<IDhcpClientCallBack> &callback)
#endif
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetDhcpClientProxy());
    return client_->RegisterDhcpClientCallBack(ifname, callback);
}

ErrCode DhcpClientImpl::StartDhcpClient(const std::string& ifname, bool bIpv6)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetDhcpClientProxy());
    return client_->StartDhcpClient(ifname, bIpv6);
}

ErrCode DhcpClientImpl::SetConfiguration(const std::string& ifname, const RouterConfig& config)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetDhcpClientProxy());
    return client_->SetConfiguration(ifname, config);
}

ErrCode DhcpClientImpl::StopDhcpClient(const std::string& ifname, bool bIpv6)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetDhcpClientProxy());
    return client_->StopDhcpClient(ifname, bIpv6);
}

ErrCode DhcpClientImpl::RenewDhcpClient(const std::string& ifname)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetDhcpClientProxy());
    return client_->RenewDhcpClient(ifname);
}
}  // namespace DHCP
}  // namespace OHOS
