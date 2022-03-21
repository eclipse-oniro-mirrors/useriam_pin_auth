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

#ifndef PIN_AUTH_SERVICE_H
#define PIN_AUTH_SERVICE_H

#include <list>
#include <mutex>
#include <string>
#include "ipc_skeleton.h"
#include "nocopyable.h"
#include "singleton.h"
#include "system_ability.h"
#include "system_ability_definition.h"
#include "i_inputer_data_stub.h"
#include "iremote_inputer.h"
#include "pinauth_controller.h"
#include "pinauth_stub.h"
#include "auth_attributes.h"
#include "auth_executor_registry.h"
#include "executor_callback.h"
#include "useridm_client.h"
#include "pin_auth.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {
using AuthAttributes = AuthResPool::AuthAttributes;
using IExecutorMessenger = AuthResPool::IExecutorMessenger;
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };

class PinAuthService : public SystemAbility, public PinAuthStub {
public:
    DECLEAR_SYSTEM_ABILITY(PinAuthService);
    DISALLOW_COPY_AND_MOVE(PinAuthService);
    PinAuthService();
    ~PinAuthService() override;

public:
    bool RegisterInputer(sptr<IRemoteInputer> inputer) override;
    void UnRegisterInputer() override;
    void OnStart() override;
    void OnStop() override;
    void ActuatorInfoQuery();

private:
    void OnResult(uint32_t resultCode);
    bool CheckPermission(const std::string &permission);
    class MngIQCallback : public AuthResPool::QueryCallback {
    public:
        DISALLOW_COPY_AND_MOVE(MngIQCallback);
        explicit MngIQCallback(PinAuthService *service) : service_(service)
        {
        }
        virtual ~MngIQCallback() = default;
        void OnResult(uint32_t resultCode) override
        {
            service_->OnResult(resultCode);
        }

    private:
        std::shared_ptr<PinAuthService> service_;
    };

    int32_t OnBeginExecute(uint64_t scheduleId, std::vector<uint8_t> &publicKey,
        std::shared_ptr<AuthResPool::AuthAttributes> commandAttrs);
    int32_t OnEndExecute(uint64_t scheduleId, std::shared_ptr<AuthAttributes> consumerAttr);
    int32_t OnSetProperty(std::shared_ptr<AuthResPool::AuthAttributes> properties);
    int32_t OnGetProperty(std::shared_ptr<AuthResPool::AuthAttributes> conditions,
        std::shared_ptr<AuthAttributes> values);
    void OnMessengerReady(const sptr<IExecutorMessenger> &messenger);

    class MngExCallback : public AuthResPool::ExecutorCallback {
    public:
        DISALLOW_COPY_AND_MOVE(MngExCallback);
        explicit MngExCallback(PinAuthService *service) : service_(service)
        {
        }
        virtual ~MngExCallback() = default;

        int32_t OnBeginExecute(uint64_t scheduleId, std::vector<uint8_t> &publicKey,
            std::shared_ptr<AuthAttributes> commandAttrs) override
        {
            return service_->OnBeginExecute(scheduleId, publicKey, commandAttrs);
        }

        int32_t OnSetProperty(std::shared_ptr<AuthResPool::AuthAttributes> properties) override
        {
            return service_->OnSetProperty(properties);
        }

        int32_t OnGetProperty(std::shared_ptr<AuthResPool::AuthAttributes> conditions,
            std::shared_ptr<AuthResPool::AuthAttributes> values) override
        {
            return service_->OnGetProperty(conditions, values);
        }

        void OnMessengerReady(const sptr<IExecutorMessenger> &messenger) override
        {
            service_->OnMessengerReady(messenger);
        }

        int32_t OnEndExecute(uint64_t sessionId, std::shared_ptr<AuthAttributes> consumerAttr) override
        {
            return service_->OnEndExecute(sessionId, consumerAttr);
        }

    private:
        std::shared_ptr<PinAuthService> service_;
    };

    ServiceRunningState serviceRunningState_ = ServiceRunningState::STATE_NOT_START;
    std::shared_ptr<AuthResPool::AuthExecutor> executor_;
    std::shared_ptr<MngIQCallback> mngIQ_;
    std::shared_ptr<MngExCallback> mngEx_;
    std::shared_ptr<PinAuth> pin_;
    uint64_t executorID_ = 0;
    std::mutex mutex_;
    sptr<IExecutorMessenger> messenger_;

    class ReconciliationCallback : public UserIDM::GetInfoCallback {
    public:
        DISALLOW_COPY_AND_MOVE(ReconciliationCallback);
        ReconciliationCallback() = default;
        virtual ~ReconciliationCallback() = default;

        void OnGetInfo(std::vector<UserIDM::CredentialInfo> &info) override;
    };
};
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS

#endif // PIN_AUTH_SERVICE_H
