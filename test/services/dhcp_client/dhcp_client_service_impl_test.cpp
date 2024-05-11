/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "dhcp_logger.h"
#include "dhcp_client_service_impl.h"
#include "dhcp_client_state_machine.h"
#include "dhcp_define.h"
#include "securec.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpClientServiceImplTest");

using namespace testing::ext;
using namespace ::testing;
namespace OHOS {
namespace DHCP {
constexpr int ADDRESS_ARRAY_SIZE = 12;
class DhcpClientServiceImplTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        dhcpClientImpl = std::make_unique<OHOS::DHCP::DhcpClientServiceImpl>();
    }
    virtual void TearDown()
    {
        if (dhcpClientImpl != nullptr) {
            dhcpClientImpl.reset(nullptr);
        }
    }
public:
    std::unique_ptr<OHOS::DHCP::DhcpClientServiceImpl> dhcpClientImpl;
};

HWTEST_F(DhcpClientServiceImplTest, IsNativeProcessTest, TestSize.Level1)
{
    ASSERT_TRUE(dhcpClientImpl != nullptr);
    DHCP_LOGE("enter IsNativeProcess fail Test");

    const std::string& ifname = "wlan0";
    bool bIpv6 = true;
    EXPECT_EQ(DHCP_E_PERMISSION_DENIED, dhcpClientImpl->StartDhcpClient(ifname, bIpv6));
    bIpv6 = false;
    EXPECT_EQ(DHCP_E_PERMISSION_DENIED, dhcpClientImpl->StopDhcpClient(ifname, bIpv6));
    EXPECT_EQ(DHCP_E_PERMISSION_DENIED, dhcpClientImpl->RenewDhcpClient(ifname));
}

HWTEST_F(DhcpClientServiceImplTest, OnStartTest, TestSize.Level1)
{
    DHCP_LOGE("enter OnStartTest");
    dhcpClientImpl->OnStart();
}

HWTEST_F(DhcpClientServiceImplTest, OnStopTest, TestSize.Level1)
{
    DHCP_LOGE("enter OnStopTest");
    dhcpClientImpl->OnStop();
}

HWTEST_F(DhcpClientServiceImplTest, InitTest, TestSize.Level1)
{
    DHCP_LOGE("enter InitTest");
    dhcpClientImpl->Init();
}

HWTEST_F(DhcpClientServiceImplTest, StartOldClientTest, TestSize.Level1)
{
    DHCP_LOGE("enter StartOldClientTest");
    ASSERT_TRUE(dhcpClientImpl != nullptr);

    std::string ifname = "wlan0";
    bool bIpv6 = true;
    DhcpClient client;
    client.ifName = ifname;
    client.isIpv6 = bIpv6;
    EXPECT_EQ(DHCP_E_FAILED, dhcpClientImpl->StartOldClient(ifname, bIpv6, client));

    client.pStaStateMachine = new DhcpClientStateMachine(client.ifName);
    EXPECT_EQ(DHCP_E_SUCCESS, dhcpClientImpl->StartOldClient(ifname, bIpv6, client));
}

HWTEST_F(DhcpClientServiceImplTest, StartNewClientTest, TestSize.Level1)
{
    DHCP_LOGE("enter StartNewClientTest");
    ASSERT_TRUE(dhcpClientImpl != nullptr);

    std::string ifname = "";
    bool bIpv6 = false;
    EXPECT_EQ(DHCP_E_SUCCESS, dhcpClientImpl->StartNewClient(ifname, bIpv6));
}

HWTEST_F(DhcpClientServiceImplTest, IsRemoteDiedTest, TestSize.Level1)
{
    DHCP_LOGE("enter IsRemoteDiedTest");
    ASSERT_TRUE(dhcpClientImpl != nullptr);

    EXPECT_EQ(true, dhcpClientImpl->IsRemoteDied());
}

HWTEST_F(DhcpClientServiceImplTest, DhcpIpv4ResultSuccessTest, TestSize.Level1)
{
    DHCP_LOGE("enter DhcpIpv4ResultSuccessTest");
    ASSERT_TRUE(dhcpClientImpl != nullptr);
    struct DhcpIpResult ipResult;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClientImpl->DhcpIpv4ResultSuccess(ipResult));

    ipResult.code = PUBLISH_CODE_SUCCESS;
    dhcpClientImpl->m_mapClientCallBack.emplace(std::make_pair("wlan0", nullptr));
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClientImpl->DhcpIpv4ResultSuccess(ipResult));

    ipResult.code = PUBLISH_CODE_TIMEOUT;
    dhcpClientImpl->m_mapClientCallBack.emplace(std::make_pair("wlan0", nullptr));
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClientImpl->DhcpIpv4ResultSuccess(ipResult));

    ipResult.code = PUBLISH_CODE_FAILED;
    dhcpClientImpl->m_mapClientCallBack.emplace(std::make_pair("wlan0", nullptr));
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClientImpl->DhcpIpv4ResultSuccess(ipResult));
    dhcpClientImpl->m_mapClientCallBack.clear();
}

HWTEST_F(DhcpClientServiceImplTest, DhcpIpv4ResultFailTest, TestSize.Level1)
{
    DHCP_LOGE("enter DhcpIpv4ResultFailTest");
    ASSERT_TRUE(dhcpClientImpl != nullptr);
    struct DhcpIpResult ipResult;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClientImpl->DhcpIpv4ResultFail(ipResult));

    dhcpClientImpl->m_mapClientCallBack.emplace(std::make_pair("wlan0", nullptr));
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClientImpl->DhcpIpv4ResultFail(ipResult));
    dhcpClientImpl->m_mapClientCallBack.clear();

    DhcpClient client;
    dhcpClientImpl->m_mapClientService.emplace(std::make_pair("wlan0", client));
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClientImpl->DhcpIpv4ResultFail(ipResult));
    dhcpClientImpl->m_mapClientService.clear();
}

HWTEST_F(DhcpClientServiceImplTest, DhcpIpv4ResultTimeOutTest, TestSize.Level1)
{
    DHCP_LOGE("enter DhcpIpv4ResultTimeOutTest");
    ASSERT_TRUE(dhcpClientImpl != nullptr);
    std::string ifname;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClientImpl->DhcpIpv4ResultTimeOut(ifname));
    ifname = "wlan0";
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClientImpl->DhcpIpv4ResultTimeOut(ifname));

    dhcpClientImpl->m_mapClientCallBack.emplace(std::make_pair("wlan0", nullptr));
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClientImpl->DhcpIpv4ResultTimeOut(ifname));
    dhcpClientImpl->m_mapClientCallBack.clear();

    DhcpClient client;
    dhcpClientImpl->m_mapClientService.emplace(std::make_pair("wlan0", client));
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClientImpl->DhcpIpv4ResultTimeOut(ifname));
    dhcpClientImpl->m_mapClientService.clear();
}

HWTEST_F(DhcpClientServiceImplTest, DhcpIpv6ResulCallbackTest, TestSize.Level1)
{
    DHCP_LOGE("enter DhcpIpv6ResulCallbackTest");
    ASSERT_TRUE(dhcpClientImpl != nullptr);
    std::string ifname;
    DhcpIpv6Info info;
    dhcpClientImpl->DhcpIpv6ResulCallback(ifname, info);

    ASSERT_TRUE(strncpy_s(info.globalIpv6Addr, DHCP_INET6_ADDRSTRLEN, " 192.168.1.10", ADDRESS_ARRAY_SIZE) == EOK);
    dhcpClientImpl->DhcpIpv6ResulCallback(ifname, info);

    ASSERT_TRUE(strncpy_s(info.routeAddr, DHCP_INET6_ADDRSTRLEN, " 192.168.1.1", ADDRESS_ARRAY_SIZE) == EOK);
    dhcpClientImpl->DhcpIpv6ResulCallback(ifname, info);

    ASSERT_TRUE(strncpy_s(info.globalIpv6Addr, DHCP_INET6_ADDRSTRLEN, "292.168.1.10", ADDRESS_ARRAY_SIZE) == EOK);
    dhcpClientImpl->DhcpIpv6ResulCallback(ifname, info);

    dhcpClientImpl->m_mapClientCallBack.emplace(std::make_pair("wlan0", nullptr));
    ifname = "wlan0";
    dhcpClientImpl->DhcpIpv6ResulCallback(ifname, info);
    dhcpClientImpl->m_mapClientCallBack.clear();

    sptr<IDhcpClientCallBack> mclientCallback;
    dhcpClientImpl->m_mapClientCallBack.emplace(std::make_pair("wlan0", mclientCallback));
    dhcpClientImpl->DhcpIpv6ResulCallback(ifname, info);
    dhcpClientImpl->m_mapClientCallBack.clear();
}

HWTEST_F(DhcpClientServiceImplTest, PushDhcpResultTest, TestSize.Level1)
{
    DHCP_LOGE("enter PushDhcpResultTest");
    ASSERT_TRUE(dhcpClientImpl != nullptr);
    std::string ifname;
    OHOS::DHCP::DhcpResult result;
    result.iptype = 1;
    result.isOptSuc = true;
    dhcpClientImpl->PushDhcpResult(ifname, result);

    ifname = "wlan";
    dhcpClientImpl->PushDhcpResult(ifname, result);
}

HWTEST_F(DhcpClientServiceImplTest, CheckDhcpResultExistTest, TestSize.Level1)
{
    DHCP_LOGE("enter CheckDhcpResultExistTest");
    ASSERT_TRUE(dhcpClientImpl != nullptr);
    std::string ifname;
    OHOS::DHCP::DhcpResult result;
    result.iptype = 1;
    result.isOptSuc = true;
    dhcpClientImpl->CheckDhcpResultExist(ifname, result);
}

HWTEST_F(DhcpClientServiceImplTest, DhcpIpv6ResultTimeOutTest, TestSize.Level1)
{
    DHCP_LOGI("DhcpIpv6ResultTimeOutTest enter!");
    std::string ifname = "wlan0";
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClientImpl->DhcpIpv6ResultTimeOut(ifname));
}

HWTEST_F(DhcpClientServiceImplTest, DhcpFreeIpv6Test, TestSize.Level1)
{
    DHCP_LOGI("DhcpFreeIpv6Test enter!");
    std::string ifname = "wlan0";
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClientImpl->DhcpFreeIpv6(ifname));
}
}
}
