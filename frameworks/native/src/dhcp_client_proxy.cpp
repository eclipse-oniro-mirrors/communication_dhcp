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
#include <unistd.h>
#include "dhcp_client_proxy.h"
#include "dhcp_manager_service_ipc_interface_code.h"
#include "dhcp_client_callback_stub.h"
#include "dhcp_c_utils.h"
#include "dhcp_errcode.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpClientProxy");

namespace OHOS {
namespace DHCP {
static sptr<DhcpClientCallBackStub> g_dhcpClientCallBackStub =
    sptr<DhcpClientCallBackStub>(new (std::nothrow)DhcpClientCallBackStub());

DhcpClientProxy::DhcpClientProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IDhcpClient>(impl),
    remote_(nullptr), mRemoteDied(false), deathRecipient_(nullptr)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (impl) {
        if (!impl->IsProxyObject()) {
            DHCP_LOGW("not proxy object!");
            return;
        }
        deathRecipient_ = new (std::nothrow)DhcpClientDeathRecipient(*this);
        if (deathRecipient_ == nullptr) {
            DHCP_LOGW("deathRecipient_ is nullptr!");
        }
        if (!impl->AddDeathRecipient(deathRecipient_)) {
            DHCP_LOGW("AddDeathRecipient failed!");
            return;
        }
        remote_ = impl;
        DHCP_LOGI("AddDeathRecipient success! ");
    }
}

DhcpClientProxy::~DhcpClientProxy()
{
    DHCP_LOGI("enter ~DhcpClientProxy!");
    RemoveDeathRecipient();
}

void DhcpClientProxy::RemoveDeathRecipient(void)
{
    DHCP_LOGI("enter RemoveDeathRecipient!");
    std::lock_guard<std::mutex> lock(mutex_);
    if (remote_ == nullptr) {
        DHCP_LOGI("remote_ is nullptr!");
        return;
    }
    if (deathRecipient_ == nullptr) {
        DHCP_LOGI("deathRecipient_ is nullptr!");
        return;
    }
    remote_->RemoveDeathRecipient(deathRecipient_);
    remote_ = nullptr;
}

void DhcpClientProxy::OnRemoteDied(const wptr<IRemoteObject> &remoteObject)
{
    DHCP_LOGW("Remote service is died! remoteObject: %{private}p", &remoteObject);
    mRemoteDied = true;
    RemoveDeathRecipient();
    if (g_dhcpClientCallBackStub == nullptr) {
        DHCP_LOGE("g_deviceCallBackStub is nullptr");
        return;
    }
    if (g_dhcpClientCallBackStub != nullptr) {
        g_dhcpClientCallBackStub->SetRemoteDied(true);
    }
}

bool DhcpClientProxy::IsRemoteDied(void)
{
    if (mRemoteDied) {
        DHCP_LOGW("IsRemoteDied! remote is died now!");
    }
    return mRemoteDied;
}

ErrCode DhcpClientProxy::RegisterDhcpClientCallBack(const std::string& ifname,
    const sptr<IDhcpClientCallBack> &callback)
{
    if (mRemoteDied) {
        DHCP_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return DHCP_E_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    data.WriteInt32(0);

    if (g_dhcpClientCallBackStub == nullptr) {
        DHCP_LOGE("g_dhcpClientCallBackStub is nullptr");
        return DHCP_E_FAILED;
    }
    g_dhcpClientCallBackStub->RegisterCallBack(callback);

    if (!data.WriteRemoteObject(g_dhcpClientCallBackStub->AsObject())) {
        DHCP_LOGE("WriteRemoteObject failed!");
        return DHCP_E_FAILED;
    }

    data.WriteString(ifname);
    DHCP_LOGI("%{public}s, calling uid:%{public}d, ifname:%{public}s", __func__, GetCallingUid(), ifname.c_str());
    int error = Remote()->SendRequest(static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_REG_CALL_BACK),
        data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed, code is %{public}d",
            static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_REG_CALL_BACK), error);
        return DHCP_E_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGE("exception failed, exception:%{public}d", exception);
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("RegisterDhcpClientCallBack ok, exception:%{public}d", exception);
    return DHCP_E_SUCCESS;
}

ErrCode DhcpClientProxy::StartDhcpClient(const std::string& ifname, bool bIpv6)
{
    DHCP_LOGI("DhcpClientProxy enter StartDhcpClient mRemoteDied:%{public}d", mRemoteDied);
    if (mRemoteDied) {
        DHCP_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return DHCP_E_FAILED;
    }

    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    data.WriteInt32(0);
    data.WriteString(ifname); 
    data.WriteBool(bIpv6);
    DHCP_LOGI("%{public}s, calling uid:%{public}d, ifname:%{public}s, bIpv6:%{public}d", __func__, GetCallingUid(),
        ifname.c_str(), bIpv6);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_START_DHCP_CLIENT), data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed, code is %{public}d",
            static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_START_DHCP_CLIENT), error);
        return DHCP_E_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGE("exception failed, exception:%{public}d", exception);
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("StartDhcpClient ok, exception:%{public}d", exception);
    return DHCP_E_SUCCESS;
}

ErrCode DhcpClientProxy::SetConfiguration(const std::string& ifname, const RouterConfig& config)
{
    DHCP_LOGI("DhcpClientProxy enter SetConfiguration mRemoteDied:%{public}d", mRemoteDied);
    if (mRemoteDied) {
        DHCP_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return DHCP_E_FAILED;
    }

    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    data.WriteInt32(0);
    data.WriteString(ifname);
    data.WriteString(config.bssid);
    DHCP_LOGI("%{public}s, calling uid:%{public}d, ifname:%{public}s", __func__, GetCallingUid(), ifname.c_str());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_SET_CONFIG), data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed, code is %{public}d",
            static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_SET_CONFIG), error);
        return DHCP_E_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGE("exception failed, exception:%{public}d", exception);
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("SetConfiguration ok, exception:%{public}d", exception);
    return DHCP_E_SUCCESS;
}

ErrCode DhcpClientProxy::StopDhcpClient(const std::string& ifname, bool bIpv6)
{
    DHCP_LOGI("DhcpClientProxy enter StopDhcpClient mRemoteDied:%{public}d", mRemoteDied);
    if (mRemoteDied) {
        DHCP_LOGI("failed to `%{public}s`,remote service is died!", __func__);
        return DHCP_E_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGI("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    data.WriteInt32(0);
    data.WriteString(ifname); 
    data.WriteBool(bIpv6);
    DHCP_LOGI("%{public}s, calling uid:%{public}d, ifname:%{public}s, bIpv6:%{public}d", __func__, GetCallingUid(),
        ifname.c_str(), bIpv6);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_STOP_DHCP_CLIENT), data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGI("Set Attr(%{public}d) failed, code is %{public}d",
            static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_STOP_DHCP_CLIENT), error);
        return DHCP_E_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGI("exception failed, exception:%{public}d", exception);
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("StopDhcpClient ok, exception:%{public}d", exception);
    return DHCP_E_SUCCESS;
}

ErrCode DhcpClientProxy::RenewDhcpClient(const std::string& ifname)
{
    if (mRemoteDied) {
        DHCP_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return DHCP_E_FAILED;
    }

    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    data.WriteInt32(0);
    data.WriteString(ifname); 
    DHCP_LOGI("%{public}s, calling uid:%{public}d, ifname:%{public}s", __func__, GetCallingUid(), ifname.c_str());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_RENEW_DHCP_CLIENT), data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed, code is %{public}d",
            static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_RENEW_DHCP_CLIENT), error);
        return DHCP_E_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGE("exception failed, exception:%{public}d", exception);
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("RenewDhcpClient ok, exception:%{public}d", exception);
    return DHCP_E_SUCCESS;
}
}  // namespace DHCP
}  // namespace OHOS
