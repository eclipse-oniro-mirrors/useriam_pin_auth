/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <string>
#include "pinauth_log_wrapper.h"
#include "pinauth_register.h"
#include "i_inputer.h"
#include "hilog/log.h"
#include "pinauth_test.h"

using namespace testing::ext;
namespace OHOS {
namespace UserIAM {
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
    virtual ~InputerUT()=default;
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
 * @tc.cpp: /interfaces/innerkits/src/piuauth_innerkits/src/pinauth_register.cpp
 */

/**
 * @tc.name: UseriamUtTest.UseriamUtTest_001
 * @tc.type: FUNC
 */
HWTEST_F(UseriamUtTest, UseriamUtTest_001, TestSize.Level1)
{
    PINAUTH_HILOGE(MODULE_COMMON, "**********UseriamUtTest***001***in**********");
    std::shared_ptr<IInputer> inputer = nullptr;
    EXPECT_EQ(0, PinAuthRegister::GetInstance().RegisterInputer(inputer));
    PINAUTH_HILOGE(MODULE_COMMON, "**********UseriamUtTest***001***out**********");
}

/**
 * @tc.name: UseriamUtTest.UseriamUtTest_002
 * @tc.type: FUNC
 */
HWTEST_F(UseriamUtTest, UseriamUtTest_002, TestSize.Level1)
{
    PINAUTH_HILOGE(MODULE_COMMON, "**********UseriamUtTest***002***in**********");
    std::shared_ptr<IInputer> inputer = std::make_shared<InputerUT>();
    EXPECT_EQ(!0, PinAuthRegister::GetInstance().RegisterInputer(inputer));
    PINAUTH_HILOGE(MODULE_COMMON, "**********UseriamUtTest***002***out**********");
}

/**
 * @tc.name: UseriamUtTest.UseriamUtTest_003
 * @tc.type: FUNC
 */
HWTEST_F(UseriamUtTest, UseriamUtTest_003, TestSize.Level1)
{
    PINAUTH_HILOGE(MODULE_COMMON, "**********UseriamUtTest***003***in**********");
    PinAuthRegister::GetInstance().UnRegisterInputer();
    PINAUTH_HILOGE(MODULE_COMMON, "**********UseriamUtTest***003***out**********");
}
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS