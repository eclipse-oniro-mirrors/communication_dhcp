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
#include "dhcp_client_callback_stub.h"
#include "dhcp_manager_service_ipc_interface_code.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpClientCallBackStub");
namespace OHOS {
namespace DHCP {
DhcpClientCallBackStub::DhcpClientCallBackStub() : callback_(nullptr), mRemoteDied(false)
{
    DHCP_LOGI("DhcpClientCallBackStub Enter DhcpClientCallBackStub");
}

DhcpClientCallBackStub::~DhcpClientCallBackStub()
{
    DHCP_LOGI("DhcpClientCallBackStub Enter ~DhcpClientCallBackStub");
}

int DhcpClientCallBackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DHCP_LOGI("DhcpClientCallBackStub::OnRemoteRequest, code:%{public}d", code);
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        DHCP_LOGE("Sta callback stub token verification error: %{public}d", code);
        return DHCP_E_FAILED;
    }
    int exception = data.ReadInt32();
    if (exception) {
        DHCP_LOGE("DhcpClientCallBackStub::OnRemoteRequest, got exception: %{public}d!", exception);
        return DHCP_E_FAILED;
    }
    int ret = -1;
    switch (code) {
        case static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_CBK_CMD_IP_SUCCESS_CHANGE): {
            ret = RemoteOnIpSuccessChanged(code, data, reply);
            break;
        }
        case static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_CBK_CMD_IP_FAIL_CHANGE): {
            ret = RemoteOnIpFailChanged(code, data, reply);
            break;
        }
        default: {
            ret = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
        }
    }
    DHCP_LOGI("DhcpClientCallBackStub OnRemoteRequest, ret:%{public}d", ret);
    return ret;
}

void DhcpClientCallBackStub::RegisterCallBack(const sptr<IDhcpClientCallBack> &callBack)
{
    if (callBack == nullptr) {
        DHCP_LOGE("DhcpClientCallBackStub:callBack is nullptr!");
        return;
    }
    callback_ = callBack;
}

bool DhcpClientCallBackStub::IsRemoteDied() const
{
    return mRemoteDied;
}

void DhcpClientCallBackStub::SetRemoteDied(bool val)
{
    DHCP_LOGI("DhcpClientCallBackStub::SetRemoteDied, state:%{public}d!", val);
    mRemoteDied = val;
}

void DhcpClientCallBackStub::OnIpSuccessChanged(int status, const std::string& ifname, DhcpResult& result)
{
    DHCP_LOGI("DhcpClientCallBackStub::OnIpSuccessChanged, status:%{public}d!", status);
    if (callback_) {
        callback_->OnIpSuccessChanged(status, ifname, result);
    }
}

void DhcpClientCallBackStub::OnIpFailChanged(int status, const std::string& ifname, const std::string& reason)
{
    DHCP_LOGI("DhcpClientCallBackStub::OnIpFailChanged, status:%{public}d!", status);
    if (callback_) {
        callback_->OnIpFailChanged(status, ifname, reason);
    }
}


int DhcpClientCallBackStub::RemoteOnIpSuccessChanged(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    DHCP_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int state = data.ReadInt32();
    std::string ifname = data.ReadString();
    DhcpResult result;
    result.iptype = data.ReadInt32();
    result.isOptSuc = data.ReadBool();
    result.uLeaseTime = data.ReadInt32();
    result.uAddTime = data.ReadInt32();
    result.uGetTime = data.ReadInt32();
    result.strYourCli = data.ReadString();
    result.strServer = data.ReadString();
    result.strSubnet = data.ReadString();
    result.strDns1 = data.ReadString();
    result.strDns2 = data.ReadString();
    result.strRouter1 = data.ReadString();
    result.strRouter2 = data.ReadString();
    result.strVendor = data.ReadString();
    result.strLinkIpv6Addr = data.ReadString();
    result.strRandIpv6Addr = data.ReadString();
    result.strLocalAddr1 = data.ReadString();
    result.strLocalAddr2 = data.ReadString();
    int size = reply.ReadInt32();
    if (state == DHCP_E_SUCCESS) {
        for (int i = 0; i < size; i++) {
            std::string str = reply.ReadString();
            result.vectorDnsAddr.push_back(str);
        }
    }
    OnIpSuccessChanged(state, ifname, result);
    reply.WriteInt32(0);
    return 0;
}

int DhcpClientCallBackStub::RemoteOnIpFailChanged(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    DHCP_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int state = data.ReadInt32();
    std::string ifname = data.ReadString();
    std::string reason = data.ReadString();
    OnIpFailChanged(state, ifname, reason);
    reply.WriteInt32(0);
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS