/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_DHCP_IPC_LITE_ADAPTER_H
#define OHOS_DHCP_IPC_LITE_ADAPTER_H

#define DHCP_CLIENT_LITE "dhcpclientlite"
#define DHCP_FEATRUE_CLIENT "dhcpclient"

#define DHCP_SERVICE_LITE "dhcpserverlite"
#define DHCP_FEATRUE_SERVER "dhcpserver"

#define IPC_DATA_SIZE_BIG 2048
#define IPC_DATA_SIZE_MID 512
#define IPC_DATA_SIZE_SMALL 256
#define MAX_IPC_OBJ_COUNT 5

struct IpcOwner {
    int funcId;
    int exception;
    int retCode;
    void *variable;
};

#endif