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

#include <mutex>
#include "nocopyable.h"
#include <map>
#include "driver_manager.h"
#include "pinauth_hdi_factory.h"
#include "parameter.h"
#include "system_ability.h"
#include "system_ability_definition.h"
#include "pinauth_stub.h"

namespace OHOS {
namespace UserIAM {
namespace PinAuth {

class PinAuthService : public SystemAbility, public PinAuthStub {
public:
    DECLEAR_SYSTEM_ABILITY(PinAuthService);
    DISALLOW_COPY_AND_MOVE(PinAuthService);
    PinAuthService();
    static std::shared_ptr<PinAuthService> GetInstance();
    void OnStart() override;
    void OnStop() override;
    void RegisterResourcePool();
    bool RegisterInputer(sptr<IRemoteInputer> inputer) override;
    void UnRegisterInputer() override;
    bool CheckPermission(const std::string &permission);

private:
    void StartDriverManager();
    void ConfigDriverManager();
    void StopDriverManager();
    static std::mutex mutex_;
    static std::shared_ptr<PinAuthService> instance_;

};
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS

#endif // PIN_AUTH_SERVICE_H
