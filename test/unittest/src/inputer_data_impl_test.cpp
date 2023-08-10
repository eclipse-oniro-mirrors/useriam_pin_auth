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

#include "inputer_data_impl_test.h"

#include "iam_ptr.h"
#include "inputer_data_impl.h"
#include "mock_inputer_set_data.h"
#include "scrypt.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void InputerDataImplTest::SetUpTestCase()
{
}

void InputerDataImplTest::TearDownTestCase()
{
}

void InputerDataImplTest::SetUp()
{
}

void InputerDataImplTest::TearDown()
{
}

HWTEST_F(InputerDataImplTest, InputerDataImplTest001, TestSize.Level0)
{
    int32_t testAuthSubType = 10000;
    uint32_t testAlgoVersion = 0;
    bool testIsEnroll = false;
    std::vector<uint8_t> testSalt = {1, 2, 3, 4, 5};
    std::vector<uint8_t> testData = {6, 7, 8, 9};

    auto scryptPtr = Common::MakeUnique<Scrypt>(testSalt);
    EXPECT_NE(scryptPtr, nullptr);
    std::vector<uint8_t> testScrypt = scryptPtr->GetScrypt(testData, testAlgoVersion);

    sptr<MockInputerSetData> tempInputerSetData(new (std::nothrow) MockInputerSetData());
    EXPECT_NE(tempInputerSetData, nullptr);

    EXPECT_CALL(*tempInputerSetData, OnSetData(_, _))
        .Times(Exactly(1))
        .WillOnce([&testAuthSubType, &testScrypt](int32_t authSubType, std::vector<uint8_t> data) {
            EXPECT_EQ(authSubType, testAuthSubType);
            EXPECT_THAT(data, ElementsAreArray(testScrypt));
            return;
        });

    auto inputerDataImpl = Common::MakeShared<InputerDataImpl>(testSalt, tempInputerSetData,
        testAlgoVersion, testIsEnroll);
    EXPECT_NE(inputerDataImpl, nullptr);

    inputerDataImpl->OnSetData(testAuthSubType, testData);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
