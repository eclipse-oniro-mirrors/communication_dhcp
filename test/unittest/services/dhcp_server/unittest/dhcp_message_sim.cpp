/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dhcp_message_sim.h"
#include <cstdio>
#include <cstdint>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <fcntl.h>
#include "dhcp_logger.h"
#include "dhcp_option.h"
#include "dhcp_server_ipv4.h"
#include "address_utils.h"
#include "securec.h"
#include "common_util.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpMessageSimulator");

using namespace OHOS::DHCP;

constexpr int OPT_MESSAGE_TYPE_LEGTH = 1;
constexpr uint8_t OPT_HEADER_LENGTH = 2;
constexpr uint8_t MAGIC_COOKIE_LENGTH = 4;
constexpr uint32_t DHCP_MAGIC_COOKIE = 0x63825363;

DhcpMsgManager& DhcpMsgManager::GetInstance()
{
    static DhcpMsgManager gMessageManager;
    return gMessageManager;
}

int DhcpMsgManager::SendTotal()
{
    int total = 0;
    m_sendQueueLocker.lock();
    total = m_sendMessages.size();
    m_sendQueueLocker.unlock();
    return total;
}

int DhcpMsgManager::RecvTotal()
{
    int total = 0;
    m_recvQueueLocker.lock();
    total = m_recvMessages.size();
    m_recvQueueLocker.unlock();
    return total;
}

bool DhcpMsgManager::FrontSendMsg(DhcpMessage *msg)
{
    int retval = false;
    if (!msg) {
        return retval;
    }
    m_sendQueueLocker.lock();
    if (!m_sendMessages.empty()) {
        DhcpMessage fmsg = m_sendMessages.front();
        if (memcpy_s(msg, sizeof(DhcpMessage), &fmsg, sizeof(DhcpMessage)) == EOK) {
            retval = true;
        }
    }
    m_sendQueueLocker.unlock();
    return retval;
}

void DhcpMsgManager::PopSendMsg()
{
    m_sendQueueLocker.lock();
    if (m_sendMessages.size() > 0) {
        m_sendMessages.pop();
    }
    m_sendQueueLocker.unlock();
}

void DhcpMsgManager::PopRecvMsg()
{
    m_recvQueueLocker.lock();
    if (!m_recvMessages.empty()) {
        m_recvMessages.pop();
    }
    m_recvQueueLocker.unlock();
}

int DhcpMsgManager::PushSendMsg(const DhcpMessage &msg)
{
    m_sendQueueLocker.lock();
    m_sendMessages.push(msg);
    m_sendQueueLocker.unlock();
    return 1;
}

int DhcpMsgManager::PushRecvMsg(const DhcpMessage &msg)
{
    m_recvQueueLocker.lock();
    m_recvMessages.push(msg);
    m_recvQueueLocker.unlock();
    return 1;
}

void DhcpMsgManager::SetClientIp(uint32_t ipAddr)
{
    m_clientIpAddress = ipAddr;
}
uint32_t DhcpMsgManager::GetClientIp() const
{
    return m_clientIpAddress;
}

int FillHwAddr(uint8_t *dst, size_t dsize, uint8_t *src, size_t ssize)
{
    if (!dst || !src) {
        return DHCP_FALSE;
    }
    if (ssize > dsize) {
        return DHCP_FALSE;
    }
    if (memset_s(dst, dsize, 0, dsize) != EOK) {
        return DHCP_FALSE;
    }
    if (memcpy_s(dst, dsize, src, ssize) != EOK) {
        return DHCP_FALSE;
    }
    return DHCP_TRUE;
}

DhcpClientContext *InitialDhcpClient(DhcpClientConfig *config)
{
    DHCP_LOGD("init dhcp client.");
    if (!config) {
        return nullptr;
    }
    DhcpClientContext *context = reinterpret_cast<DhcpClientContext *>(calloc(1, sizeof(DhcpClientContext)));
    if (context == nullptr) {
        DHCP_LOGE("failed to calloc client context.");
        return nullptr;
    }
    if (memset_s(context, sizeof(DhcpClientContext), 0, sizeof(DhcpClientContext)) != EOK) {
        DHCP_LOGE("failed to reset client context.");
        free(context);
        return nullptr;
    }
    if (memset_s(context->config.ifname, IFACE_NAME_SIZE, '\0', IFACE_NAME_SIZE) != EOK) {
        DHCP_LOGE("failed to reset interface name.");
        free(context);
        return nullptr;
    }
    if (strncpy_s(context->config.ifname, IFACE_NAME_SIZE, config->ifname, strlen(config->ifname)) != EOK) {
        DHCP_LOGE("failed to set interface name.");
        free(context);
        return nullptr;
    }
    if (!FillHwAddr(context->config.chaddr, DHCP_HWADDR_LENGTH, config->chaddr, MAC_ADDR_LENGTH)) {
        DHCP_LOGE("failed to set chaddr.");
        free(context);
        return nullptr;
    }
    context->clientFd = 1;
    return context;
}

static int ParseDhcpOptions(PDhcpMsgInfo msg)
{
    int ret;
    PDhcpOptionNode pNode = msg->options.first->next;
    DhcpOption endOpt = {END_OPTION, 0, {0}};
    PushBackOption(&msg->options, &endOpt);
    int replyOptsLength = 0;
    uint8_t *current = msg->packet.options, olen = MAGIC_COOKIE_LENGTH;
    uint32_t cookie = htonl(DHCP_MAGIC_COOKIE);
    if (memcpy_s(current, olen, &cookie, olen) != EOK) {
        DHCP_LOGE("memcpy cookie out of options buffer!");
        return RET_FAILED;
    }
    replyOptsLength += olen;
    current += olen;
    ret = RET_SUCCESS;
    while (pNode && (uint32_t)pNode->option.length < DHCP_OPTION_SIZE) {
        if ((uint32_t)pNode->option.code == END_OPTION) {
            olen = OPT_HEADER_LENGTH + 1;
        } else {
            olen = OPT_HEADER_LENGTH + pNode->option.length;
        }
        if (memcpy_s(current, olen, &pNode->option, olen) != EOK) {
            DHCP_LOGE("memcpy current option out of options buffer!");
            ret = RET_FAILED;
            break;
        }
        current += olen;
        replyOptsLength += olen;
        if ((uint32_t)pNode->option.code == END_OPTION) {
            break;
        }
        pNode = pNode->next;
        if (replyOptsLength >= DHCP_OPTIONS_SIZE) {
            DHCP_LOGE("current option out of options buffer!");
            ret = RET_FAILED;
            break;
        }
    }
    msg->length += replyOptsLength;
    return ret;
}

int SendDhcpMessage(const DhcpClientContext *ctx, PDhcpMsgInfo msg)
{
    if (!ctx || !msg) {
        DHCP_LOGE("client context or message pointer is null.");
        return RET_FAILED;
    }
    if (ParseDhcpOptions(msg) != RET_SUCCESS) {
        DHCP_LOGE("failed to parse dhcp message info.");
        return RET_FAILED;
    }
    DhcpMsgManager::GetInstance().PushSendMsg(msg->packet);
    return RET_SUCCESS;
}

static uint32_t GetXid(int update)
{
    static uint32_t currXid = Tmspsec();
    if (update) {
        currXid = Tmspsec();
    }
    return currXid;
}

int InitMessage(DhcpClientContext *ctx, PDhcpMsgInfo msg, uint8_t msgType)
{
    DHCP_LOGD("init dhcp message...");
    if (!ctx) {
        DHCP_LOGD("client context pointer is null.");
        return DHCP_FALSE;
    }
    if (!msg) {
        DHCP_LOGD("dhcp message pointer is null.");
        return DHCP_FALSE;
    }
    if (memset_s(msg, sizeof(DhcpMsgInfo), 0, sizeof(DhcpMsgInfo)) != EOK) {
        DHCP_LOGD("message info pointer is null.");
        return DHCP_FALSE;
    }
    if (InitOptionList(&msg->options) != RET_SUCCESS) {
        DHCP_LOGD("failed to initialize dhcp client options.");
        return DHCP_FALSE;
    }
    if (!FillHwAddr(msg->packet.chaddr, DHCP_HWADDR_LENGTH, ctx->config.chaddr, MAC_ADDR_LENGTH)) {
        return DHCP_FALSE;
    }
    msg->packet.op = BOOTREQUEST;
    msg->packet.htype = 0x01;
    msg->packet.hlen = MAC_ADDR_LENGTH;
    if (msgType == DHCPDISCOVER) {
        msg->packet.xid = GetXid(DHCP_TRUE);
    } else {
        msg->packet.xid = GetXid(DHCP_FALSE);
    }

    if (DhcpMsgManager::GetInstance().GetClientIp() != 0) {
        DhcpOption optReqIp = {REQUESTED_IP_ADDRESS_OPTION, 0, {0}};
        AppendAddressOption(&optReqIp, DhcpMsgManager::GetInstance().GetClientIp());
        PushFrontOption(&msg->options, &optReqIp);
    }

    DhcpOption optMsgType = {DHCP_MESSAGE_TYPE_OPTION, OPT_MESSAGE_TYPE_LEGTH, {msgType, 0}};
    PushFrontOption(&msg->options, &optMsgType);

    PDhcpOption pEndOpt = GetOption(&msg->options, END_OPTION);
    if (pEndOpt == NULL) {
        DhcpOption endOpt = {END_OPTION, 0, {0}};
        PushBackOption(&msg->options, &endOpt);
    }
    return DHCP_TRUE;
}

int DhcpDiscover(DhcpClientContext *ctx)
{
    if (!ctx) {
        return RET_FAILED;
    }
    DhcpMsgInfo msgInfo;
    if (!InitMessage(ctx, &msgInfo, DHCPDISCOVER)) {
        DHCP_LOGD("failed to init dhcp message.");
        return RET_FAILED;
    }
    if (SendDhcpMessage(ctx, &msgInfo) != RET_SUCCESS) {
        DHCP_LOGD("failed to send dhcp message.");
        return RET_FAILED;
    }
    DHCP_LOGD("send dhcp discover...");
    return RET_SUCCESS;
}

int DhcpRequest(DhcpClientContext *ctx)
{
    if (!ctx) {
        return RET_FAILED;
    }
    DhcpMsgInfo msgInfo;
    if (!InitMessage(ctx, &msgInfo, DHCPREQUEST)) {
        DHCP_LOGD("failed to init dhcp message.");
        return RET_FAILED;
    }
    if (SendDhcpMessage(ctx, &msgInfo) != RET_SUCCESS) {
        DHCP_LOGD("failed to send dhcp message.");
        return RET_FAILED;
    }
    DHCP_LOGD("send dhcp request...");
    return RET_SUCCESS;
}

int DhcpInform(DhcpClientContext *ctx)
{
    if (!ctx) {
        return RET_FAILED;
    }
    DhcpMsgInfo msgInfo;
    if (!InitMessage(ctx, &msgInfo, DHCPINFORM)) {
        DHCP_LOGD("failed to init dhcp message.");
        return RET_FAILED;
    }
    if (SendDhcpMessage(ctx, &msgInfo) != RET_SUCCESS) {
        DHCP_LOGD("failed to send dhcp message.");
        return RET_FAILED;
    }
    DHCP_LOGD("send dhcp inform...");
    return RET_SUCCESS;
}

int DhcpDecline(DhcpClientContext *ctx)
{
    if (!ctx) {
        return RET_FAILED;
    }
    DhcpMsgInfo msgInfo;
    if (!InitMessage(ctx, &msgInfo, DHCPDECLINE)) {
        DHCP_LOGD("failed to init dhcp message.");
        return RET_FAILED;
    }
    if (SendDhcpMessage(ctx, &msgInfo) != RET_SUCCESS) {
        DHCP_LOGD("failed to send dhcp message.");
        return RET_FAILED;
    }
    DHCP_LOGD("send dhcp decline...");
    return RET_SUCCESS;
}

int DhcpRelease(DhcpClientContext *ctx)
{
    if (!ctx) {
        return RET_FAILED;
    }
    DhcpMsgInfo msgInfo;
    if (!InitMessage(ctx, &msgInfo, DHCPRELEASE)) {
        DHCP_LOGD("failed to init dhcp message.");
        return RET_FAILED;
    }
    if (SendDhcpMessage(ctx, &msgInfo) != RET_SUCCESS) {
        DHCP_LOGD("failed to send dhcp message.");
        return RET_FAILED;
    }
    DHCP_LOGD("send dhcp release...");
    return RET_SUCCESS;
}