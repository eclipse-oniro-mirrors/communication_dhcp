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

#ifndef OHOS_DHCP_COMMON_UTILS_H
#define OHOS_DHCP_COMMON_UTILS_H

#include <string>

namespace OHOS {
namespace DHCP {
/**
 * @Description IP address anonymization
 *
 * <p> eg: 11.11.11.1 -> 11.11.11.*
 *
 * @param str - Input MAC address
 * @return std::string - Processed MAC
 */
std::string Ipv4Anonymize(const std::string str);
}
}
#endif
