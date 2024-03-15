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
#ifndef OHOS_I_DHCP_SERVICE__CALLBACK_H
#define OHOS_I_DHCP_SERVICE__CALLBACK_H

#include <string>
#ifndef OHOS_ARCH_LITE
#include <iremote_broker.h>
#include "message_parcel.h"
#include "message_option.h"
#endif
#include "inner_api/include/dhcp_define.h"
#include "dhcp_result_event.h"
namespace OHOS {
namespace DHCP {
#ifdef OHOS_ARCH_LITE
class IDhcpServerCallBack {
#else
class IDhcpServerCallBack : public IRemoteBroker {
#endif
public:
    virtual ~IDhcpServerCallBack() {}
    virtual void OnServerStatusChanged(int status) = 0;
    virtual void OnServerLeasesChanged(const std::string& ifname, std::vector<std::string>& leases) = 0;
    virtual void OnServerSerExitChanged(const std::string& ifname) = 0;
    virtual void OnServerSuccess(const std::string& ifname, std::vector<DhcpStationInfo>& stationInfos) = 0;
#ifndef OHOS_ARCH_LITE
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.wifi.IDhcpServerCallBack");
#endif
};
}  // namespace DHCP
}  // namespace OHOS
#endif