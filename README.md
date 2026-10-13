# DHCP组件

#### 介绍
动态主机配置协议 DHCP（Dynamic Host Configuration Protocol，动态主机配置协议） 是 RFC 1541定义的标准协议，该协议允许服务器向客户端动态分配IP地址和配置信息。DHCP协议支持C/S（客户端/服务器）结构，主要分为两部分：

1、DHCP客户端：通常为网络中的手机、PC、打印机等终端设备，使用从DHCP服务器分配下来的IP信息，包括IP地址、默认网关及DNS等。

2、DHCP服务器：用于管理所有的IP网络信息，并处理客户端的DHCP请求，为接入的客户端分配IP地址、子网掩码、默认网关等内容。
#### 软件架构
软件架构说明：
如下图所示，DhcpService类提供外部管理DHCP模块服务的接口，其中包含了DHCP客户端服务的启动、停止及结果获取，DHCP服务端的启动、停止及地址池和租约表的管理等等，方便其它各子系统业务实现中调用DhcpService业务的接口。

![](figures/zh-cn_image_dhcp.png)

#### 使用说明

1. 调用类DhcpServiceApi获取IDhcpService实例；
2. 通过IDhcpService实例启动DHCP功能（Client/Server）；
3. Client端通过GetDhcpResult注册DhcpResultNotify类的回调；
4. Server端通过GetDhcpSerProExit获取DHCP Server异常退出的通知。

## 本次改动<a name="section_changes_zh"></a>

本仓针对 HiSpark AiFly（Hi3403V100）开发板进行功能适配。为便于区分，以下按“新增能力”与“原有功能增强”两部分说明。

### 新增能力

1. 新增 DHCP Lite 客户端 C 接口
    -   新增 `interfaces/kits/c/dhcp_lite_c_client_api.h`，以 `extern "C"` 方式对外暴露 `RegisterDhcpClientCallBack`、`DealWifiDhcpCache`、`StartDhcpClient`、`StopDhcpClient` 四个接口。
    -   新增实现 `frameworks/native/c_adapter/src/dhcp_lite_c_client_api.cpp`：内部通过 `DhcpClient::GetInstance(DHCP_CLIENT_ABILITY_ID)` 转发到原有 C++ 接口；`StopDhcpClient` 在成功后调用 `UnRegisterCallBack` 注销回调；入参通过 `CHECK_PTR_RETURN` 做空指针校验。

2. 新增 DHCP 客户端系统服务（小型系统）
    -   新增 `services/dhcp_client/include/dhcp_client_mgr_service_lite.h`：`DhcpClientMgrService` 继承 `Service`，提供单例 `GetInstance()` 及 `GetIdentity`、`GetServiceName`、`ServiceInitialize`、`ServiceMessageHandle`、`GetServiceTaskConfig` 实现。
    -   新增实现 `services/dhcp_client/src/dhcp_client_mgr_service_lite.cpp`：通过 `SYSEX_SERVICE_INIT(Init)` 注册到 `SAMGR_GetInstance()`，服务名为 `DHCP_CLIENT_LITE`，任务配置为 LEVEL_HIGH、PRI_NORMAL、栈 1024、队列 20、单任务。

3. 新增默认路由与 DNS 自动落盘能力
    -   在 `services/dhcp_client/src/dhcp_client_service_impl.cpp` 的 `OHOS_ARCH_LITE` 分支新增静态函数 `ExecRouteAdd`（`fork` + `execl("/bin/route", ...)` 添加默认网关）、`WriteResolvConf`（写入 `/etc/resolv.conf`）与 `SaveDefaultRouteAndDns`。
    -   IPv4 获取成功后（`DhcpIpv4ResultSuccess`）调用 `SaveDefaultRouteAndDns`，自动应用网关与 DNS。

4. 新增同步超时任务接口
    -   在 `services/utils/src/dhcp_thread.cpp` 新增 `PostSyncTimeOutTask`：基于 `std::packaged_task` 与 `std::future` 执行任务，超时返回 `ERROR_TIMEOUT`。

5. 新增构建与编译接入
    -   根 `BUILD.gn`：`ohos_lite` 下 deps 新增 `$DHCP_ROOT_DIR/frameworks/native:dhcp_client_sdk`。
    -   `services/dhcp_client/BUILD.gn`：sources 新增 `dhcp_result_store_manager.cpp`、`dhcp_thread.cpp`、`dhcp_client_feature_lite.cpp`、`dhcp_client_mgr_service_lite.cpp`，并补充 include 路径与 `services/utils:dhcp_utils` 依赖。
    -   `services/utils/BUILD.gn`：sources 新增 `dhcp_permission_utils.cpp`，并补充 bounds_checking_function、hilog 相关头文件与依赖。

### 原有功能增强

1. 原有 DHCP Lite 客户端代理（`DhcpClientProxy`）增强
    -   原有功能：通过 SAMGR 获取客户端 feature 接口，并转发注册回调、启动/停止 DHCP 等请求。
    -   本次增强：新增 `Initialize()`，在 feature 未就绪时最多重试 30 次、每次间隔 300ms 等待，`DhcpClientImpl::Init` 改用该接口；返回码统一为 `DHCP_E_*` / `DHCP_SUCCESS` / `DHCP_FAILED`，并补齐 `StopClientSa`、`IsRemoteDied` 实现与缺失头文件。

2. 原有回调桩（`DhcpClientCallBackStub`）序列化读取加固
    -   原有功能：解析 IPC 数据并回调上层 IP 成功/失败事件。
    -   本次增强：抽出 `ReadStringValue`、`ReadDhcpResultBase`、`ReadDhcpResultStrings` 复用解析逻辑，`RemoteOnIpSuccessChanged` 增加 `data` 空指针校验；指针转换由 `static_cast` 改为 `reinterpret_cast`；回调桩补充 `callbackMutex_` 成员与 `<mutex>` 头文件，修复小型系统编译 libdhcp_client_sdk 失败的问题。

3. 原有客户端 Stub（`dhcp_client_stub_lite.cpp`）调整
    -   原有功能：在服务侧解析请求并调用对应处理函数。
    -   本次增强：`OnStartDhcpClient` 移除多余的 `ReadRemoteObject` 读取，并补充 `config.ifname`、`config.bssid` 赋值；`OnStopDhcpClient` 同样移除多余的 `ReadRemoteObject`；字符串读取指针转换改为 `reinterpret_cast`。

4. 原有服务端实现（`dhcp_server_impl.cpp`）修正
    -   原有功能：小型系统下初始化 DHCP 服务端代理并缓存客户端句柄。
    -   本次增强：修正初始化时误用 `clientProxy` 变量的问题，改为使用 `serverProxy` 并去除冗余空指针判断，避免代理为空导致初始化异常。

5. 原有事件结果拷贝（`dhcp_event.cpp`）加固
    -   原有功能：将 DHCP 结果中的地址信息拷贝为扩展结构。
    -   本次增强：拷贝 DNS 地址时跳过空字符串并记录日志，避免写入无效 DNS 地址。

6. 原有客户端 Feature（`dhcp_client_feature_lite.cpp`）调整
    -   原有功能：提供 DHCP 客户端 feature 的消息处理入口。
    -   本次增强：日志宏由 `LOGI`/`LOGE` 改为 `DHCP_LOGI`/`DHCP_LOGE` 并新增 `DEFINE_DHCPLOG_DHCP_LABEL`；修正 feature 实例类型（`DhcpServerFeature` → `DhcpClientFeature`）。

7. 原有 IPC Lite 适配头（`dhcp_ipc_lite_adapter.h`）补全
    -   补充 `#include "ipc_skeleton.h"`，保证 Lite IPC 相关符号可见。

#### 相关仓

communication_wifi
