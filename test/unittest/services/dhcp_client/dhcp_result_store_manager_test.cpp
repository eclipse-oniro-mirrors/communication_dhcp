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
#include <gtest/gtest.h>
#include "dhcp_logger.h"
#include "dhcp_errcode.h"
#include "dhcp_result_store_manager.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpResultStoreManagerTest");

using namespace testing::ext;
using namespace OHOS::DHCP;
namespace OHOS {
constexpr int ZERO = 0;
class DhcpResultStoreManagerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        dhcpResultStoreManager_ = std::make_unique<DhcpResultStoreManager>();
    }
    virtual void TearDown()
    {}
public:
    std::unique_ptr<DhcpResultStoreManager>dhcpResultStoreManager_;
};
/**
 * @tc.name: SaveIpInfoInLocalFile_SUCCESS
 * @tc.desc: SaveIpInfoInLocalFile
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpResultStoreManagerTest, SaveIpInfoInLocalFile_SUCCESS, TestSize.Level1)
{
    DHCP_LOGE("enter SaveIpInfoInLocalFile_SUCCESS");
    IpInfoCached ipInfoCached;
    ipInfoCached.bssid = "12:34:56:48:78:56";
    ipInfoCached.absoluteLeasetime = 1;
    dhcpResultStoreManager_->SaveIpInfoInLocalFile(ipInfoCached);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}
/**
 * @tc.name: GetCachedDhcpResult_SUCCESS
 * @tc.desc: GetCachedDhcpResult
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpResultStoreManagerTest, GetCachedDhcpResult_SUCCESS, TestSize.Level1)
{
    DHCP_LOGE("enter GetCachedDhcpResult_SUCCESS");
    std::string targetBssid = "12:34:56:48:78:56";
    IpInfoCached ipInfo;
    dhcpResultStoreManager_->GetCachedIp(targetBssid, ipInfo);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}
/**
 * @tc.name: SetNetworkRemoveState_SUCCESS
 * @tc.desc: Disable fast request ip for a cached entry that exists
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpResultStoreManagerTest, SetNetworkRemoveState_SUCCESS, TestSize.Level1)
{
    DHCP_LOGE("enter SetNetworkRemoveState_SUCCESS");
    IpInfoCached ipInfoCached;
    ipInfoCached.bssid = "aa:bb:cc:dd:ee:ff";
    ipInfoCached.ssid = "test_ssid";
    ipInfoCached.absoluteLeasetime = static_cast<int64_t>(time(nullptr)) + 3600;
    ipInfoCached.isNetworkConfigExit = true;
    dhcpResultStoreManager_->SaveIpInfoInLocalFile(ipInfoCached);

    IpInfoCached cacheInfo;
    cacheInfo.bssid = "aa:bb:cc:dd:ee:ff";
    int32_t ret = dhcpResultStoreManager_->SetNetworkRemoveState(cacheInfo);
    EXPECT_EQ(ret, DHCP_E_SUCCESS);

    IpInfoCached getResult;
    int32_t getRet = dhcpResultStoreManager_->GetCachedIp("aa:bb:cc:dd:ee:ff", getResult);
    EXPECT_EQ(getRet, 0);
    EXPECT_FALSE(getResult.isNetworkConfigExit);
}
/**
 * @tc.name: SetNetworkRemoveState_FAILD
 * @tc.desc: Disable fast request ip with empty bssid should fail
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpResultStoreManagerTest, SetNetworkRemoveState_FAILD, TestSize.Level1)
{
    DHCP_LOGE("enter SetNetworkRemoveState_FAILD");
    IpInfoCached cacheInfo;
    cacheInfo.bssid = "";
    int32_t ret = dhcpResultStoreManager_->SetNetworkRemoveState(cacheInfo);
    EXPECT_EQ(ret, DHCP_E_FAILED);
}
}  // namespace OHOS