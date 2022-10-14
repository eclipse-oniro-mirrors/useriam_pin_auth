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

#include "inputer_set_data_proxy_test.h"

#include "iam_common_defines.h"
#include "iam_ptr.h"
#include "inputer_set_data_proxy.h"
#include "mock_inputer_data_impl.h"
#include "mock_remote_object.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void InputerSetDataProxyTest::SetUpTestCase()
{
}

void InputerSetDataProxyTest::TearDownTestCase()
{
}

void InputerSetDataProxyTest::SetUp()
{
}

void InputerSetDataProxyTest::TearDown()
{
}

HWTEST_F(InputerSetDataProxyTest, InputerSetDataProxyTest, TestSize.Level0)
{
    int32_t testAuthSubType = 10000;
    std::vector<uint8_t> testSalt = {1, 2, 3, 4, 5, 6};
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<InputerSetDataProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    auto service = Common::MakeShared<MockInputerDataImpl>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnSetData(_, _))
        .Times(Exactly(1))
        .WillOnce([&testAuthSubType](int32_t authSubType, std::vector<uint8_t> data) {
            EXPECT_EQ(authSubType, testAuthSubType);
            EXPECT_THAT(data, ElementsAre(1, 2, 3, 4, 5, 6));
            return;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            return service->OnRemoteRequest(code, data, reply, option);
        });
    proxy->OnSetData(testAuthSubType, testSalt);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
