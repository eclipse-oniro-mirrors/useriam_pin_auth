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

#include "pin_auth_executor_callback_manager_test.h"

#include <gtest/gtest.h>

#include "iam_logger.h"
#include "iam_ptr.h"
#include "pin_auth_executor_callback_hdi.h"
#include "pin_auth_executor_callback_manager.h"

#define LOG_TAG "PIN_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void PinAuthExecutorCallbackManagerTest::SetUpTestCase()
{
}

void PinAuthExecutorCallbackManagerTest::TearDownTestCase()
{
}

void PinAuthExecutorCallbackManagerTest::SetUp()
{
}

void PinAuthExecutorCallbackManagerTest::TearDown()
{
}

HWTEST_F(PinAuthExecutorCallbackManagerTest, PinAuthExecutorCallbackManagerTest001, TestSize.Level0)
{
    uint64_t scheduleId = 0;
    auto pinAuthExecutorCallback = new (std::nothrow) PinAuthExecutorCallbackHdi(nullptr, nullptr, 0, true);
    EXPECT_TRUE(pinAuthExecutorCallback != nullptr);

    bool ret = PinAuthExecutorCallbackManager::GetInstance().SetCallback(scheduleId, pinAuthExecutorCallback);
    EXPECT_TRUE(ret);
    ret = PinAuthExecutorCallbackManager::GetInstance().SetCallback(scheduleId, pinAuthExecutorCallback);
    EXPECT_TRUE(!ret);
    auto callback = PinAuthExecutorCallbackManager::GetInstance().GetCallbackLock(scheduleId);
    EXPECT_TRUE(callback != nullptr);
    PinAuthExecutorCallbackManager::GetInstance().RemoveCallback(scheduleId);

    delete pinAuthExecutorCallback;
}

HWTEST_F(PinAuthExecutorCallbackManagerTest, PinAuthExecutorCallbackManagerTest002, TestSize.Level0)
{
    uint64_t scheduleId = 0;

    bool ret = PinAuthExecutorCallbackManager::GetInstance().SetCallback(scheduleId, nullptr);
    EXPECT_TRUE(!ret);
    auto callback = PinAuthExecutorCallbackManager::GetInstance().GetCallbackLock(scheduleId);
    EXPECT_TRUE(callback == nullptr);
}

} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS