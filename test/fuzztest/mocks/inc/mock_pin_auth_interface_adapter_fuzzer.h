/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef MOCK_PIN_AUTH_INTERFACE_ADAPTER_FUZZER_H
#define MOCK_PIN_AUTH_INTERFACE_ADAPTER_FUZZER_H

#include "pin_auth_interface_adapter.h"
#include "pin_auth_hdi.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace OHOS;
using namespace OHOS::HDI::PinAuth::V3_0;
class MockPinAuthInterfaceAdapterFuzzer : public PinAuthInterfaceAdapter {
public:
    virtual ~MockPinAuthInterfaceAdapterFuzzer() = default;
    sptr<IPinAuthInterface> Get() override
    {
        sptr<IPinAuthInterface> mockIPinAuthInterface(new (std::nothrow) MockIPinAuthInterface());
        return mockIPinAuthInterface;
    }
private:
    class MockIPinAuthInterface : public IPinAuthInterface {
    public:
        virtual ~MockIPinAuthInterface() = default;
        int32_t GetExecutorList(std::vector<sptr<IAllInOneExecutor>>& allInOneExecutors,
            std::vector<sptr<IVerifier>>& verifiers, std::vector<sptr<ICollector>>& collectors)
        {
            return 0;
        }
    };
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

#endif // MOCK_PIN_AUTH_INTERFACE_ADAPTER_FUZZER_H