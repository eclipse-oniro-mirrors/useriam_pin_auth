/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "services_modules_driver_pin_auth_interface_adapter_test.h"
#include "pin_auth_interface_adapter.h"
#include "mock_pin_auth_interface_adapter_fuzzer.h"

#include <openssl/sha.h>

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void ServicesModulesDriverPinAuthInterfaceAdapterTest::SetUpTestCase()
{
}

void ServicesModulesDriverPinAuthInterfaceAdapterTest::TearDownTestCase()
{
}

void ServicesModulesDriverPinAuthInterfaceAdapterTest::SetUp()
{
}

void ServicesModulesDriverPinAuthInterfaceAdapterTest::TearDown()
{
}

HWTEST_F(ServicesModulesDriverPinAuthInterfaceAdapterTest, OnRemoteDied001, TestSize.Level0)
{
    std::shared_ptr<PinAuthInterfaceAdapter> adapter = Common::MakeShared<MockPinAuthInterfaceAdapterFuzzer>();
    EXPECT_NO_THROW(adapter->Get());
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
