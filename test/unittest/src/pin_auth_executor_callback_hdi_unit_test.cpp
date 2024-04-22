/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "iam_logger.h"
#include "iam_ptr.h"

#include "pin_auth_executor_callback_hdi.h"
#include "iam_common_defines.h"
#include "mock_iexecute_callback.h"

#define LOG_TAG "PIN_AUTH_SA"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::UserIam::UserAuth;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using IamResultCode = OHOS::UserIam::UserAuth::ResultCode;
class PinAuthExecutorCallbackHdiUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PinAuthExecutorCallbackHdiUnitTest ::SetUpTestCase()
{
}

void PinAuthExecutorCallbackHdiUnitTest ::TearDownTestCase()
{
}

void PinAuthExecutorCallbackHdiUnitTest ::SetUp()
{
}

void PinAuthExecutorCallbackHdiUnitTest ::TearDown()
{
}

HWTEST_F(PinAuthExecutorCallbackHdiUnitTest, PinAuthExecutorCallback_OnResult_001, TestSize.Level0)
{
    static const std::map<ResultCode, IamResultCode> data = {{SUCCESS, IamResultCode::SUCCESS},
        {FAIL, IamResultCode::FAIL}, {GENERAL_ERROR, IamResultCode::GENERAL_ERROR},
        {CANCELED, IamResultCode::CANCELED}, {TIMEOUT, IamResultCode::TIMEOUT},
        {BUSY, IamResultCode::BUSY},
        {INVALID_PARAMETERS, IamResultCode::INVALID_PARAMETERS},
        {LOCKED, IamResultCode::LOCKED}};

    for (const auto &pair : data) {
        auto executeCallback = MakeShared<UserIam::UserAuth::MockIExecuteCallback>();
        ASSERT_TRUE(executeCallback != nullptr);
        std::vector<uint8_t> testExtraInfo = {1, 2, 3, 4, 5, 6};
        EXPECT_CALL(*executeCallback, OnResult(_, _))
            .Times(Exactly(3))
            .WillRepeatedly([&pair, &testExtraInfo](int32_t result, const std::vector<uint8_t> &extraInfo) {
                EXPECT_TRUE(result == pair.second);
                EXPECT_TRUE(testExtraInfo.size() == extraInfo.size());
                EXPECT_TRUE(std::equal(extraInfo.begin(), extraInfo.end(), testExtraInfo.begin()));
            });
        std::shared_ptr<PinAuthAllInOneHdi> pinAuthAllInOneHdi = MakeShared<PinAuthAllInOneHdi>(nullptr);
        const uint32_t tokenId = 123;
        const uint64_t scheduleId = 1;
        PinAuthExecutorCallbackHdi callbackHdi1(executeCallback, pinAuthAllInOneHdi, tokenId, false, scheduleId);
        callbackHdi1.OnResult(pair.first, testExtraInfo);
        PinAuthExecutorCallbackHdi callbackHdi2(executeCallback, pinAuthAllInOneHdi, tokenId, true, scheduleId);
        callbackHdi2.OnResult(pair.first, testExtraInfo);
        std::shared_ptr<PinAuthCollectorHdi> pinAuthCollectorHdi = MakeShared<PinAuthCollectorHdi>(nullptr);
        PinAuthExecutorCallbackHdi callbackHdi3(executeCallback, pinAuthCollectorHdi, tokenId, true, scheduleId);
        callbackHdi2.OnResult(pair.first, testExtraInfo);
    }
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
