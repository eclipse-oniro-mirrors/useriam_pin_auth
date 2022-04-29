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

#include "pinauth_executor_callback_hdi.h"
#include "i_inputter_data_impl.h"
#include "pinauth_log_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
    PinAuthExecutorCallbackHDI::PinAuthExecutorCallbackHDI(std::shared_ptr<UserAuth::IExecuteCallback>
        frameworkCallback, uint64_t callerUid) : frameworkCallback_(frameworkCallback) , callerUid_(callerUid) {}
    int32_t PinAuthExecutorCallbackHDI::OnResult(int32_t code, const std::vector<uint8_t>& extraInfo)
    {
        PINAUTH_HILOGI(MODULE_SERVICE, "OnResult %{public}d", code);
        frameworkCallback_->OnResult(code, extraInfo);
        return SUCCESS;
    }

    int32_t PinAuthExecutorCallbackHDI::OnGetData(uint64_t scheduleId, const std::vector<uint8_t>& salt,
        uint64_t authSubType)
    {
        PINAUTH_HILOGI(MODULE_SERVICE, "Start");
        sptr<IRemoteInputer> inputer = pinAuthManager_->getInputerLock(callerUid_);
        sptr<IInputerDataImpl> iInputerDataImpl = new IInputerDataImpl(scheduleId);
        inputer->OnGetData(authSubType, salt, iInputerDataImpl);
        return SUCCESS;
    }

} // PinAuth
} // UserIAM
} // OHOS