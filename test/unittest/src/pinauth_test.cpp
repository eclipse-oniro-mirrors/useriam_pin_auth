/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "pinauth_test.h"
#include <gtest/gtest.h>
#include <string>
#include "iam_logger.h"
#include "pinauth_register.h"
#include "i_inputer.h"

#define LOG_TAG "PIN_AUTH_SDK"

using namespace testing::ext;
namespace OHOS {
namespace UserIam {
namespace PinAuth {
class UseriamUtTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};
class InputerUT : public IInputer {
public:
    void OnGetData(int32_t authSubType, std::shared_ptr<IInputerData> inputerData)override {}
    virtual ~InputerUT() = default;
};

void UseriamUtTest::SetUpTestCase(void)
{
}

void UseriamUtTest::TearDownTestCase(void)
{
}

void UseriamUtTest::SetUp()
{
}

void UseriamUtTest::TearDown()
{
}
/**
 * @tc.cpp: /interfaces/innerkits/src/piuauth_innerkits/src/pinauth_register_impl.cpp
 */

/**
 * @tc.name: UseriamUtTest.UseriamUtTest001
 * @tc.type: FUNC
 */
HWTEST_F(UseriamUtTest, UseriamUtTest001, TestSize.Level1)
{
    IAM_LOGI("**********UseriamUtTest***001***in**********");
    std::shared_ptr<IInputer> inputer = nullptr;
    EXPECT_EQ(false, PinAuthRegister::GetInstance().RegisterInputer(inputer));
    IAM_LOGI("**********UseriamUtTest***001***out**********");
}

/**
 * @tc.name: UseriamUtTest.UseriamUtTest002
 * @tc.type: FUNC
 */
HWTEST_F(UseriamUtTest, UseriamUtTest002, TestSize.Level1)
{
    IAM_LOGI("**********UseriamUtTest***002***in**********");
    std::shared_ptr<IInputer> inputer = std::make_shared<InputerUT>();
    EXPECT_EQ(false, PinAuthRegister::GetInstance().RegisterInputer(inputer));
    IAM_LOGI("**********UseriamUtTest***002***out**********");
}

/**
 * @tc.name: UseriamUtTest.UseriamUtTest003
 * @tc.type: FUNC
 */
HWTEST_F(UseriamUtTest, UseriamUtTest003, TestSize.Level1)
{
    IAM_LOGI("**********UseriamUtTest***003***in**********");
    PinAuthRegister::GetInstance().UnRegisterInputer();
    IAM_LOGI("**********UseriamUtTest***003***out**********");
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS