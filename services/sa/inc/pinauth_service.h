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
#include <map>
#include "nocopyable.h"
#include "system_ability.h"
#include "system_ability_definition.h"
#include "pinauth_stub.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
class PinAuthService : public SystemAbility, public PinAuthStub {
public:
    DECLEAR_SYSTEM_ABILITY(PinAuthService);
    PinAuthService();
    static std::shared_ptr<PinAuthService> GetInstance();

    // SystemAbility
    void OnStart() override;
    void OnStop() override;
    bool RegisterInputer(sptr<IRemoteInputer> inputer) override;
    void UnRegisterInputer() override;
    bool CheckPermission(const std::string &permission);

private:
    PinAuthService(PinAuthService &) = delete;
    PinAuthService &operator=(PinAuthService &) = delete;
    PinAuthService(PinAuthService &&) = delete;
    PinAuthService &operator=(PinAuthService &&) = delete;
    void StartDriverManager();
    static std::mutex mutex_;
    static std::shared_ptr<PinAuthService> instance_;
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // PIN_AUTH_SERVICE_H
