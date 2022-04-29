/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef PIN_AUTH_EXECUTOR_CALLBACK_HDI
#define PIN_AUTH_EXECUTOR_CALLBACK_HDI

#include <stdint.h>
#include <vector>
#include "v1_0/executor_callback_stub.h"
#include "i_inputer_proxy.h"
#include "iexecute_callback.h"
#include "iexecutor_messenger.h"
#include "pinauth_manager.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
    namespace PinHDI = OHOS::HDI::Pinauth::V1_0;
    class PinAuthExecutorCallbackHDI : public PinHDI::ExecutorCallbackStub {
    public:
        PinAuthExecutorCallbackHDI(std::shared_ptr<UserAuth::IExecuteCallback> frameworkCallback, uint64_t callerUid);
        virtual ~PinAuthExecutorCallbackHDI() = default;
        int32_t OnResult(int32_t code, const std::vector<uint8_t>& extraInfo) override;
        int32_t OnGetData(uint64_t scheduleId, const std::vector<uint8_t>& salt, uint64_t authSubType) override;

    private:
        std::shared_ptr<UserAuth::IExecuteCallback> frameworkCallback_;
        std::shared_ptr<IInputerProxy> IInputerProxyCallback_;
        std::shared_ptr<PinAuthManager> pinAuthManager_;
        uint64_t callerUid_ = 0;
    };
} // PinAuth
} // UserIAM
} // OHOS

#endif // PIN_AUTH_EXECUTOR_CALLBACK_HDI