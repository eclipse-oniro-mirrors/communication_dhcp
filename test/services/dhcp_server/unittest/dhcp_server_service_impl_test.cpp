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

#include "dhcp_server_service_impl.h"
#include "dhcp_errcode.h"
#include "system_func_mock.h"
#include "dhcp_function.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpServerServiceTest");

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::DHCP;
namespace OHOS {
namespace DHCP {
class DhcpServerServiceTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        pServerServiceImpl = std::make_unique<OHOS::DHCP::DhcpServerServiceImpl>();
    }
    virtual void TearDown()
    {
        if (pServerServiceImpl != nullptr) {
            pServerServiceImpl.reset(nullptr);
        }
    }
public:
    std::unique_ptr<OHOS::DHCP::DhcpServerServiceImpl> pServerServiceImpl;
};

HWTEST_F(DhcpServerServiceTest, DhcpServerServiceImplTest, TestSize.Level1)
{
    ASSERT_TRUE(pServerServiceImpl != nullptr);
    DHCP_LOGE("enter IsNativeProcess is fail test.");

    std::string ifname = "wlan0";
    std::string tagName = "sta";
    DhcpRange putRange;
    putRange.iptype = 0;
    DhcpRange setRange;
    setRange.iptype = 0;
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->StopDhcpServer("wlan1"));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->PutDhcpRange(tagName, putRange));
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->RemoveDhcpRange(tagName, putRange));
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->RemoveAllDhcpRange(tagName));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->SetDhcpRange(ifname, setRange));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->StartDhcpServer(ifname));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->SetDhcpName(ifname, tagName));

    std::vector<std::string> vecLeases;
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->GetDhcpClientInfos(ifname, vecLeases));
    std::string strLeaseTime;
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->UpdateLeasesTime(strLeaseTime));
}

HWTEST_F(DhcpServerServiceTest, DhcpServerService_Test5, TestSize.Level1)
{
    DHCP_LOGE("enter DhcpServerService_Test5.");
    ASSERT_TRUE(pServerServiceImpl != nullptr);

    EXPECT_EQ(DHCP_OPT_ERROR, pServerServiceImpl->CheckAndUpdateConf(""));
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->CheckAndUpdateConf("wlan1"));

    std::string ipRange;
    EXPECT_EQ(DHCP_OPT_ERROR, pServerServiceImpl->GetUsingIpRange("", ipRange));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->GetUsingIpRange("ww", ipRange));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->GetUsingIpRange("wlan0", ipRange));

    DhcpRange checkRange;
    EXPECT_EQ(false, pServerServiceImpl->CheckIpAddrRange(checkRange));
    checkRange.iptype = 0;
    checkRange.strStartip = "192.168.0";
    checkRange.strEndip = "192.168.1";
    EXPECT_EQ(false, pServerServiceImpl->CheckIpAddrRange(checkRange));
    checkRange.strStartip = "192.168.0.49";
    checkRange.strEndip = "192.168.1";
    EXPECT_EQ(false, pServerServiceImpl->CheckIpAddrRange(checkRange));
    checkRange.strEndip = "192.168.0.1";
    EXPECT_EQ(false, pServerServiceImpl->CheckIpAddrRange(checkRange));

    checkRange.iptype = 1;
    checkRange.strStartip = "fe80:fac8";
    EXPECT_EQ(false, pServerServiceImpl->CheckIpAddrRange(checkRange));
    checkRange.strStartip = "fe80::fac8";
    checkRange.strEndip = "fe80:fac8";
    EXPECT_EQ(false, pServerServiceImpl->CheckIpAddrRange(checkRange));

    std::string ifname;
    EXPECT_EQ(DHCP_OPT_ERROR, pServerServiceImpl->AddSpecifiedInterface(ifname));
    ifname = "wlan";
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->AddSpecifiedInterface(ifname));
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->AddSpecifiedInterface(ifname));

    ifname.clear();
    EXPECT_EQ(DHCP_OPT_ERROR, pServerServiceImpl->DelSpecifiedInterface(ifname));
    ifname = "wlan";
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->DelSpecifiedInterface(ifname));
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->DelSpecifiedInterface(ifname));

    std::string strFile = DHCP_SERVER_LEASES_FILE + "." + ifname;
    std::string strTestData = "dhcp server leases file test";
    ASSERT_TRUE(DhcpFunction::CreateFile(strFile, strTestData));
    std::vector<std::string> vecLeases;
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->GetDhcpClientInfos(ifname, vecLeases));
    ASSERT_TRUE(DhcpFunction::RemoveFile(strFile));
}

HWTEST_F(DhcpServerServiceTest, CreateDefaultConfigFileTest, TestSize.Level1)
{
    ASSERT_TRUE(pServerServiceImpl != nullptr);
    std::string strFile;

    strFile = "";
    EXPECT_EQ(DHCP_OPT_ERROR, pServerServiceImpl->CreateDefaultConfigFile(strFile));
    strFile = "wlan0";
    EXPECT_EQ(DHCP_OPT_SUCCESS, pServerServiceImpl->CreateDefaultConfigFile(strFile));
}

HWTEST_F(DhcpServerServiceTest, OnStartTest, TestSize.Level1)
{
    DHCP_LOGE("enter OnStartTest");
    pServerServiceImpl->OnStart();
}

HWTEST_F(DhcpServerServiceTest, OnStopTest, TestSize.Level1)
{
    DHCP_LOGE("enter OnStopTest");
    pServerServiceImpl->OnStop();
}

HWTEST_F(DhcpServerServiceTest, IsRemoteDiedTest, TestSize.Level1)
{
    DHCP_LOGE("enter IsRemoteDiedTest");
    ASSERT_TRUE(pServerServiceImpl != nullptr);

    EXPECT_EQ(true, pServerServiceImpl->IsRemoteDied());
}

HWTEST_F(DhcpServerServiceTest, DeleteLeaseFileTest, TestSize.Level1)
{
    DHCP_LOGI("enter DeleteLeaseFileTest");
    ASSERT_TRUE(pServerServiceImpl != nullptr);
    std::string ifname;
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->DeleteLeaseFile(ifname));
}
}
}
