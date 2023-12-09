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
#ifndef OHOS_DHCP_CLIENT_H
#define OHOS_DHCP_CLIENT_H

#include "i_dhcp_client_callback.h"
#include "dhcp_errcode.h"

namespace OHOS {
namespace Wifi {
class DhcpClient {
public:
    static std::shared_ptr<DhcpClient> GetInstance(int systemAbilityId);
    virtual ~DhcpClient();
#ifdef OHOS_ARCH_LITE
    virtual ErrCode RegisterDhcpClientCallBack(const std::string& ifname,
        const std::shared_ptr<IDhcpClientCallBack> &callback) = 0;
#else
    virtual ErrCode RegisterDhcpClientCallBack(const std::string& ifname,
        const sptr<IDhcpClientCallBack> &callback) = 0;
#endif
    virtual ErrCode StartDhcpClient(const std::string& ifname, bool bIpv6) = 0;
    virtual ErrCode StopDhcpClient(const std::string& ifname, bool bIpv6) = 0;
    virtual ErrCode RenewDhcpClient(const std::string& ifname) = 0;
};
}  // namespace Wifi
}  // namespace OHOS
#endif