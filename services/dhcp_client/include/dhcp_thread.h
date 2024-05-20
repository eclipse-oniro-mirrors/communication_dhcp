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

#ifndef DHCP_THREAD_H
#define DHCP_THREAD_H

#include <string>
#include <memory>
#include "dhcp_client_def.h"
#ifndef OHOS_ARCH_LITE
#include "common_timer_errors.h"
#include "timer.h"
#endif

namespace OHOS {
namespace DHCP {
class DhcpThread {
public:
    using Callback = std::function<void()>;

    explicit DhcpThread(const std::string &threadName);
    ~DhcpThread();
/**
 * @submit sync task to Handler
 *
 * @param Callback - Input task
 * @return bool - true: submit success, false: submit failed
 */
    bool PostSyncTask(const Callback &callback);
/**
 * @submit Async task to Handler
 *
 * @param Callback - Input task
 * @param delayTime - Wait delayTime ms excute task
 * @return bool - true: submit success, false: submit failed
 */
    bool PostAsyncTask(const Callback &callback, int64_t delayTime = 0);
/**
 * @submit Async task to Handler
 *
 * @param Callback - Input task
 * @param name - Describer of task
 * @param delayTime - Wait delayTime ms excute task
 * @return bool - true: submit success, false: submit failed
 */
    bool PostAsyncTask(const Callback &callback, const std::string &name, int64_t delayTime = 0);
/**
 * @Remove Async task
 *
 * @param name - Describer of task
 */
    void RemoveAsyncTask(const std::string &name);

private:
    class DhcpThreadImpl;
    std::unique_ptr<DhcpThreadImpl> ptr;
};

#ifndef OHOS_ARCH_LITE
#ifdef DHCP_FFRT_ENABLE
class DhcpTimer {
    public:
        static constexpr uint32_t DEFAULT_TIMEROUT = 15000;
        using TimerCallback = std::function<void()>;
        static DhcpTimer *GetInstance(void);

        DhcpTimer();
        ~DhcpTimer();

        EnumErrCode Register(const TimerCallback &callback, uint32_t &outTimerId, uint32_t interval = DEFAULT_TIMEROUT,
            bool once = true);
        void UnRegister(uint32_t timerId);
    public:
        std::unique_ptr<DhcpThread> timer_{nullptr};
        uint32_t timerIdInit = 0;
};
#else
    class DhcpTimer {
    public:
        static constexpr uint32_t DEFAULT_TIMEROUT = 15000;
        using TimerCallback = std::function<void()>;
        static DhcpTimer *GetInstance(void);

        DhcpTimer();
        ~DhcpTimer();

        EnumErrCode Register(const TimerCallback &callback, uint32_t &outTimerId, uint32_t interval = DEFAULT_TIMEROUT,
            bool once = true);
        void UnRegister(uint32_t timerId);
    public:
        std::unique_ptr<Utils::Timer> timer_{nullptr};
    };
#endif
#endif

} // namespace DHCP
} // namespace OHOS
#endif