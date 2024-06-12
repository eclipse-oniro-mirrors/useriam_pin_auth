/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "services_pin_auth_manager_test.h"

#include <openssl/sha.h>

#include "iam_ptr.h"
#include "pin_auth_manager.h"
#include "mock_iall_in_one_executor.h"
#include "mock_icollector_executor.h"
#include "mock_inputer_get_data.h"
#include "mock_inputer_set_data.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void ServicesPinAuthManagerTest::SetUpTestCase()
{
}

void ServicesPinAuthManagerTest::TearDownTestCase()
{
}

void ServicesPinAuthManagerTest::SetUp()
{
}

void ServicesPinAuthManagerTest::TearDown()
{
}

HWTEST_F(ServicesPinAuthManagerTest, ServicesPinAuthManagerTest001, TestSize.Level0)
{
    uint32_t tokenId = 1;
    sptr<InputerGetData> inputer(nullptr);
    EXPECT_NO_THROW(PinAuthManager::GetInstance().RegisterInputer(tokenId, inputer));
}

HWTEST_F(ServicesPinAuthManagerTest, GetInputerLockTest001, TestSize.Level0)
{
    uint32_t tokenId = 1;
    sptr<InputerGetData> inputer(new (std::nothrow) MockInputerGetData());
    PinAuthManager::GetInstance().RegisterInputer(tokenId, inputer);
    EXPECT_NE(PinAuthManager::GetInstance().GetInputerLock(tokenId), nullptr);
    PinAuthManager::GetInstance().UnRegisterInputer(tokenId);
}

HWTEST_F(ServicesPinAuthManagerTest, OnRemoteDiedTest001, TestSize.Level0)
{
    uint32_t tokenId = 1;
    sptr<InputerGetData> inputer(new (std::nothrow) MockInputerGetData());
    PinAuthManager::GetInstance().RegisterInputer(tokenId, inputer);
    EXPECT_NO_THROW(PinAuthManager::GetInstance().pinAuthDeathMap_[tokenId]->OnRemoteDied(nullptr));
}

HWTEST_F(ServicesPinAuthManagerTest, OnRemoteDiedTest002, TestSize.Level0)
{
    uint32_t tokenId = 1;
    sptr<InputerGetData> inputer(new (std::nothrow) MockInputerGetData());
    PinAuthManager::GetInstance().RegisterInputer(tokenId, inputer);
    EXPECT_NO_THROW(PinAuthManager::GetInstance().pinAuthDeathMap_[tokenId]->OnRemoteDied(inputer));
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
