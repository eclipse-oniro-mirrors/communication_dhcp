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

#include <gtest/gtest.h>
#include <cstring>
#include <sys/stat.h>
#include <fcntl.h>

#include "mock_system_func.h"
#include "mock_custom_func.h"
#include "dhcp_logger.h"
#include "dhcp_client_state_machine.h"
#include "dhcp_client_def.h"
#include "dhcp_function.h"
#include "securec.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpClientStateMachineTest");

using namespace testing::ext;
using namespace OHOS::Wifi;
namespace OHOS {
namespace Wifi {
class DhcpClientStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        std::string ifnametest = "wlan0";
        dhcpClient = std::make_unique<OHOS::Wifi::DhcpClientStateMachine>(ifnametest);
    }
    virtual void TearDown()
    {
        if (dhcpClient != nullptr) {
            dhcpClient.reset(nullptr);
        }
    }
public:
    std::unique_ptr<OHOS::Wifi::DhcpClientStateMachine> dhcpClient;
};

HWTEST_F(DhcpClientStateMachineTest, ExecDhcpRenew_SUCCESS, TestSize.Level1)
{
    DHCP_LOGE("enter ExecDhcpRenew_SUCCESS");
    MockSystemFunc::SetMockFlag(true);

    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_)).WillRepeatedly(Return(0));

    dhcpClient->SetIpv4State(DHCP_STATE_INIT);
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->ExecDhcpRenew());
    dhcpClient->SetIpv4State(DHCP_STATE_REQUESTING);
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->ExecDhcpRenew());
    dhcpClient->SetIpv4State(DHCP_STATE_BOUND);
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->ExecDhcpRenew());
    dhcpClient->SetIpv4State(DHCP_STATE_RENEWING);
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->ExecDhcpRenew());
    dhcpClient->SetIpv4State(DHCP_STATE_INITREBOOT);
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->ExecDhcpRenew());
    MockSystemFunc::SetMockFlag(false);
}

HWTEST_F(DhcpClientStateMachineTest, TEST_FAILED, TestSize.Level1)
{
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->SetIpv4State(-1));
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->GetPacketHeaderInfo(NULL, 0));
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->GetPacketCommonInfo(NULL));
}
/**
 * @tc.name: PublishDhcpResultEvent_Fail1
 * @tc.desc: PublishDhcpResultEvent()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, PublishDhcpResultEvent_Fail1, TestSize.Level1)
{
    DhcpIpResult result;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->PublishDhcpResultEvent(nullptr, PUBLISH_CODE_SUCCESS, &result));
}
/**
 * @tc.name: PublishDhcpResultEvent_Fail2
 * @tc.desc: PublishDhcpResultEvent()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, PublishDhcpResultEvent_Fail2, TestSize.Level1)
{
    DhcpIpResult result;
    char ifname[] = "testcode//";
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->PublishDhcpResultEvent(ifname, DHCP_HWADDR_LENGTH, &result));
}
/**
 * @tc.name: PublishDhcpResultEvent_Fail3
 * @tc.desc: PublishDhcpResultEvent()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, PublishDhcpResultEvent_Fail3, TestSize.Level1)
{
    DhcpIpResult *result = NULL;
    char ifname[] = "testcode//";
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->PublishDhcpResultEvent(ifname, PUBLISH_CODE_SUCCESS, result));
}
/**
 * @tc.name: PublishDhcpResultEvent_Fail4
 * @tc.desc: PublishDhcpResultEvent()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, PublishDhcpResultEvent_Fail4, TestSize.Level1)
{
    DhcpIpResult result;
    char ifname[] = "testcode//";
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->PublishDhcpResultEvent(ifname, PUBLISH_CODE_SUCCESS, &result));
}
/**
 * @tc.name: PublishDhcpResultEvent_Fail5
 * @tc.desc: PublishDhcpResultEvent()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, PublishDhcpResultEvent_Fail5, TestSize.Level1)
{
    DhcpIpResult result;
    char ifname[] = "testcode//";
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->PublishDhcpResultEvent(ifname, PUBLISH_CODE_FAILED, &result));
}
/**
 * @tc.name: SyncDhcpResult_Fail1
 * @tc.desc: SyncDhcpResult()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, SyncDhcpResult_Fail1, TestSize.Level1)
{
    struct DhcpPacket *packet = nullptr;
    DhcpIpResult result;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->SyncDhcpResult(packet, &result));
}
/**
 * @tc.name: SyncDhcpResult_Fail2
 * @tc.desc: SyncDhcpResult()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, SyncDhcpResult_Fail2, TestSize.Level1)
{
    struct DhcpPacket packet;
    DhcpIpResult *result = nullptr;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->SyncDhcpResult(&packet, result));
}
/**
 * @tc.name: SyncDhcpResult_Fail3
 * @tc.desc: SyncDhcpResult()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, SyncDhcpResult_Fail3, TestSize.Level1)
{
    struct DhcpPacket *packet = nullptr;
    DhcpIpResult *result = nullptr;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->SyncDhcpResult(packet, result));
}

/**
 * @tc.name: SyncDhcpResult_Fail4
 * @tc.desc: SyncDhcpResult()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, SyncDhcpResult_Fail4, TestSize.Level1)
{
    struct DhcpPacket packet;
    struct DhcpIpResult result;
    strcpy_s((char*)packet.sname, sizeof(packet.sname), "testcode");
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->SyncDhcpResult(&packet, &result));
}

/**
 * @tc.name: GetDHCPServerHostName_Fail1
 * @tc.desc: GetDHCPServerHostName()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, GetDHCPServerHostName_Fail1, TestSize.Level1)
{
    struct DhcpPacket *packet = nullptr;
    DhcpIpResult result;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->GetDHCPServerHostName(packet, &result));
}

/**
 * @tc.name: GetDHCPServerHostName_Fail2
 * @tc.desc: GetDHCPServerHostName()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, GetDHCPServerHostName_Fail2, TestSize.Level1)
{
    struct DhcpPacket packet;
    DhcpIpResult *result = nullptr;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->GetDHCPServerHostName(&packet, result));
}

/**
 * @tc.name: GetDHCPServerHostName_Fail3
 * @tc.desc: GetDHCPServerHostName()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, GetDHCPServerHostName_Fail3, TestSize.Level1)
{
    struct DhcpPacket *packet = nullptr;
    DhcpIpResult *result = nullptr;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->GetDHCPServerHostName(packet, result));
}

/**
 * @tc.name: GetDHCPServerHostName_Success
 * @tc.desc: GetDHCPServerHostName()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, GetDHCPServerHostName_Success, TestSize.Level1)
{
    struct DhcpPacket packet;
    struct DhcpIpResult result;
    strcpy_s((char*)packet.sname, sizeof(packet.sname), "testcode");
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->GetDHCPServerHostName(&packet, &result));
}

HWTEST_F(DhcpClientStateMachineTest, SetSocketModeTest, TestSize.Level1)
{
    DHCP_LOGE("SetSocketModeTest enter!");
    dhcpClient->SetSocketMode(1);
}

HWTEST_F(DhcpClientStateMachineTest, SendRebootTest, TestSize.Level1)
{
    DHCP_LOGE("SendRebootTest enter!");
    dhcpClient->SendReboot(nullptr, 1);
}

HWTEST_F(DhcpClientStateMachineTest, GetPacketReadSockFdTest, TestSize.Level1)
{
    DHCP_LOGE("GetPacketReadSockFdTest enter!");
    dhcpClient->GetPacketReadSockFd();
}

HWTEST_F(DhcpClientStateMachineTest, GetSigReadSockFdTest, TestSize.Level1)
{
    DHCP_LOGE("GetSigReadSockFdTest enter!");
    dhcpClient->GetSigReadSockFd();
}

HWTEST_F(DhcpClientStateMachineTest, GetDhcpTransIDTest, TestSize.Level1)
{
    DHCP_LOGE("GetDhcpTransIDTest enter!");
    dhcpClient->GetDhcpTransID();
}

HWTEST_F(DhcpClientStateMachineTest, GetPacketHeaderInfoTest, TestSize.Level1)
{
    struct DhcpPacket packet;
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->GetPacketHeaderInfo(&packet, DHCP_NAK));
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->GetPacketHeaderInfo(&packet, DHCP_FORCERENEW));
}

HWTEST_F(DhcpClientStateMachineTest, StartGetIpTimerTest, TestSize.Level1)
{
    DHCP_LOGI("StartGetIpTimerTest enter!");
    dhcpClient->StartGetIpTimer();
}

HWTEST_F(DhcpClientStateMachineTest, StopGetIpTimerTest, TestSize.Level1)
{
    DHCP_LOGI("StopGetIpTimerTest enter!");
    dhcpClient->StopGetIpTimer();
}

HWTEST_F(DhcpClientStateMachineTest, InitStartIpv4ThreadTest, TestSize.Level1)
{
    DHCP_LOGI("InitStartIpv4ThreadTest enter!");
    std::string ifname;
    bool isIpv6 = true;
    dhcpClient->InitStartIpv4Thread(ifname, isIpv6);
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->InitStartIpv4Thread(ifname, isIpv6));
    ifname = "ipv4";
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->InitStartIpv4Thread(ifname, isIpv6));
}

HWTEST_F(DhcpClientStateMachineTest, ExitIpv4Test, TestSize.Level1)
{
    DHCP_LOGI("ExitIpv4Test enter!");
    dhcpClient->ExitIpv4();
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->ExitIpv4());
}

HWTEST_F(DhcpClientStateMachineTest, StopIpv4Test, TestSize.Level1)
{
    DHCP_LOGI("StopIpv4Test enter!");
    dhcpClient->StopIpv4();
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->StopIpv4());
}

HWTEST_F(DhcpClientStateMachineTest, DhcpInitTest, TestSize.Level1)
{
    DHCP_LOGI("DhcpInitTest enter!");
    dhcpClient->DhcpInit();
}

HWTEST_F(DhcpClientStateMachineTest, DhcpStopTest, TestSize.Level1)
{
    DHCP_LOGI("DhcpStopTest enter!");
    dhcpClient->DhcpStop();
}

HWTEST_F(DhcpClientStateMachineTest, RenewingTest, TestSize.Level1)
{
    DHCP_LOGI("RenewingTest enter!");
    time_t curTimestamp = time(NULL);
    dhcpClient->Renewing(curTimestamp);
}

HWTEST_F(DhcpClientStateMachineTest, RebindingTest, TestSize.Level1)
{
    DHCP_LOGI("RebindingTest enter!");
    time_t curTimestamp = time(NULL);
    dhcpClient->Rebinding(curTimestamp);
}

HWTEST_F(DhcpClientStateMachineTest, DhcpRequestHandleTest, TestSize.Level1)
{
    DHCP_LOGI("DhcpRequestHandleTest enter!");
    time_t curTimestamp = time(NULL);
    dhcpClient->SetIpv4State(DHCP_STATE_INITREBOOT);
    dhcpClient->DhcpRequestHandle(curTimestamp);
}

HWTEST_F(DhcpClientStateMachineTest, DhcpResponseHandleTest, TestSize.Level1)
{
    DHCP_LOGI("DhcpResponseHandleTest enter!");
    time_t curTimestamp = time(NULL);
    dhcpClient->SetIpv4State(DHCP_STATE_SELECTING);
    dhcpClient->DhcpResponseHandle(curTimestamp);

    dhcpClient->SetIpv4State(DHCP_STATE_INITREBOOT);
    dhcpClient->DhcpResponseHandle(curTimestamp);
}

HWTEST_F(DhcpClientStateMachineTest, DhcpAckOrNakPacketHandleTest, TestSize.Level1)
{
    DHCP_LOGI("DhcpAckOrNakPacketHandleTest enter!");
    struct DhcpPacket *packet = nullptr;
    uint8_t type = DHCP_REQUEST;
    time_t curTimestamp = time(NULL);
    dhcpClient->DhcpAckOrNakPacketHandle(type, packet, curTimestamp);

    type = DHCP_NAK;
    dhcpClient->DhcpAckOrNakPacketHandle(type, packet, curTimestamp);

    DhcpPacket packet1;
    dhcpClient->DhcpAckOrNakPacketHandle(type, &packet1, curTimestamp);
}

HWTEST_F(DhcpClientStateMachineTest, ParseDhcpAckPacketTest, TestSize.Level1)
{
    DHCP_LOGI("ParseDhcpAckPacketTest enter!");
    struct DhcpPacket *packet = nullptr;
    time_t curTimestamp = time(NULL);
    dhcpClient->ParseDhcpAckPacket(packet, curTimestamp);

    DhcpPacket packet1;
    dhcpClient->ParseDhcpAckPacket(&packet1, curTimestamp);
}

HWTEST_F(DhcpClientStateMachineTest, ParseNetworkInfoTest, TestSize.Level1)
{
    DHCP_LOGI("ParseNetworkInfoTest enter!");
    struct DhcpPacket *packet = nullptr;
    struct DhcpIpResult *result = nullptr;
    dhcpClient->ParseNetworkInfo(packet, result);

    DhcpPacket packet1;
    DhcpIpResult result1;
    dhcpClient->ParseNetworkInfo(&packet1, &result1);
}

HWTEST_F(DhcpClientStateMachineTest, ParseOtherNetworkInfoTest, TestSize.Level1)
{
    DHCP_LOGI("ParseOtherNetworkInfoTest enter!");
    struct DhcpPacket *packet = nullptr;
    struct DhcpIpResult *result = nullptr;
    dhcpClient->ParseOtherNetworkInfo(packet, result);

    DhcpPacket packet1;
    DhcpIpResult result1;
    dhcpClient->ParseOtherNetworkInfo(&packet1, &result1);
}

HWTEST_F(DhcpClientStateMachineTest, DhcpOfferPacketHandleTest, TestSize.Level1)
{
    DHCP_LOGI("DhcpOfferPacketHandleTest enter!");
    struct DhcpPacket *packet = nullptr;
    uint8_t type = DHCP_REQUEST;
    time_t curTimestamp = time(NULL);
    dhcpClient->DhcpOfferPacketHandle(type, packet, curTimestamp);

    type = DHCP_OFFER;
    dhcpClient->DhcpOfferPacketHandle(type, packet, curTimestamp);

    DhcpPacket packet1;
    dhcpClient->DhcpOfferPacketHandle(type, &packet1, curTimestamp);
}

HWTEST_F(DhcpClientStateMachineTest, DhcpRebootTest, TestSize.Level1)
{
    DHCP_LOGE("DhcpRebootTest enter!");
    EXPECT_EQ(SOCKET_OPT_FAILED, dhcpClient->DhcpReboot(1, 1));
}

HWTEST_F(DhcpClientStateMachineTest, StartIpv4TypeTest, TestSize.Level1)
{
    DHCP_LOGI("StartIpv4TypeTest enter!");
    std::string ifname;
    bool isIpv6 = true;
    ActionMode action = ACTION_START_NEW;
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->StartIpv4Type(ifname, isIpv6, action));
}

HWTEST_F(DhcpClientStateMachineTest, GetIpTimerCallbackTest, TestSize.Level1)
{
    DHCP_LOGI("GetIpTimerCallbackTest enter!");
    dhcpClient->GetIpTimerCallback();
}

HWTEST_F(DhcpClientStateMachineTest, WriteLeaseTest, TestSize.Level1)
{
    DHCP_LOGI("WriteLeaseTest enter!");
    struct DhcpPacket *pkt = nullptr;
    EXPECT_EQ(-1, dhcpClient->WriteLease(pkt));

    DhcpPacket pkt1;
    pkt1.cookie = 1;
    dhcpClient->WriteLease(&pkt1);
}

HWTEST_F(DhcpClientStateMachineTest, FormatStringTest, TestSize.Level1)
{
    DHCP_LOGI("FormatStringTest enter!");
    struct DhcpIpResult *result = nullptr;
    dhcpClient->FormatString(result);

    DhcpIpResult result1;
    strcpy_s(result1.strYiaddr, sizeof(result1.strYiaddr), "");
    dhcpClient->FormatString(&result1);

    DhcpIpResult result2;
    strcpy_s(result2.strOptServerId, sizeof(result2.strOptServerId), "");
    dhcpClient->FormatString(&result2);

    DhcpIpResult result3;
    strcpy_s(result3.strOptSubnet, sizeof(result3.strOptSubnet), "");
    dhcpClient->FormatString(&result3);

    DhcpIpResult result4;
    strcpy_s(result4.strOptDns1, sizeof(result2.strOptDns1), "");
    dhcpClient->FormatString(&result4);

    DhcpIpResult result5;
    strcpy_s(result5.strOptDns2, sizeof(result5.strOptDns2), "");
    dhcpClient->FormatString(&result5);

    DhcpIpResult result6;
    strcpy_s(result6.strOptRouter1, sizeof(result6.strOptRouter1), "");
    dhcpClient->FormatString(&result6);

    DhcpIpResult result7;
    strcpy_s(result7.strOptRouter2, sizeof(result7.strOptRouter2), "");
    dhcpClient->FormatString(&result7);

    DhcpIpResult result8;
    strcpy_s(result8.strOptVendor, sizeof(result8.strOptVendor), "");
    dhcpClient->FormatString(&result8);
}
}
}
1