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

#include "inputer_get_data_proxy_test.h"

#include "iam_ptr.h"
#include "inputer_get_data_proxy.h"
#include "mock_inputer_get_data_service.h"
#include "mock_inputer_set_data.h"
#include "mock_remote_object.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void InputerGetDataProxyTest::SetUpTestCase()
{
}

void InputerGetDataProxyTest::TearDownTestCase()
{
}

void InputerGetDataProxyTest::SetUp()
{
}

void InputerGetDataProxyTest::TearDown()
{
}

HWTEST_F(InputerGetDataProxyTest, InputerGetDataProxyTest001, TestSize.Level0)
{
    InputerGetDataParam testParam = {
        .mode = GET_DATA_MODE_ALL_IN_ONE_AUTH,
        .authSubType = 10000,
        .algoVersion = 0,
        .algoParameter = {1, 2, 3, 4, 5, 6},
        .challenge = {2, 3, 4, 5, 6, 7},
        .inputerSetData = new (std::nothrow) MockInputerSetData(),
    };

    ASSERT_NE(testParam.inputerSetData, nullptr);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<InputerGetDataProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    auto service = Common::MakeShared<MockInputerGetDataService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnGetData(_))
        .Times(Exactly(1))
        .WillOnce([&testParam](const InputerGetDataParam &getDataParam) {
            EXPECT_EQ(getDataParam.mode, testParam.mode);
            EXPECT_EQ(getDataParam.authSubType, testParam.authSubType);
            EXPECT_EQ(getDataParam.algoVersion, testParam.algoVersion);
            EXPECT_THAT(getDataParam.algoParameter, ElementsAre(1, 2, 3, 4, 5, 6));
            EXPECT_THAT(getDataParam.challenge, ElementsAre(2, 3, 4, 5, 6, 7));
            return;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            return service->OnRemoteRequest(code, data, reply, option);
        });
    proxy->OnGetData(testParam);
}

HWTEST_F(InputerGetDataProxyTest, InputerGetDataProxyTest002, TestSize.Level0)
{
    InputerGetDataParam testParam = {
        .mode = GET_DATA_MODE_ALL_IN_ONE_AUTH,
        .authSubType = 10000,
        .algoVersion = 0,
        .algoParameter = {1, 2, 3, 4, 5, 6},
        .challenge = {2, 3, 4, 5, 6, 7},
        .inputerSetData = new (std::nothrow) MockInputerSetData(),
    };

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    ASSERT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<InputerGetDataProxy>(obj);
    ASSERT_NE(proxy, nullptr);

    proxy->OnGetData(testParam);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
