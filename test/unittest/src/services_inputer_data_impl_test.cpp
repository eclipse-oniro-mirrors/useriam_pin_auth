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

#include "services_inputer_data_impl_test.h"

#include <openssl/sha.h>

#include "iam_ptr.h"
#include "i_inputer_data_impl.h"
#include "mock_iall_in_one_executor.h"
#include "mock_icollector_executor.h"
#include "mock_inputer_set_data.h"
#include "pin_auth_all_in_one_hdi.h"
#include "pin_auth_collector_hdi.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void ServicesInputerDataImplTest::SetUpTestCase()
{
}

void ServicesInputerDataImplTest::TearDownTestCase()
{
}

void ServicesInputerDataImplTest::SetUp()
{
}

void ServicesInputerDataImplTest::TearDown()
{
}

HWTEST_F(ServicesInputerDataImplTest, ServicesInputerDataImplEnrollTest001, TestSize.Level0)
{
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    std::shared_ptr<PinAuthAllInOneHdi> allInOnePtr = std::make_shared<PinAuthAllInOneHdi>(nullptr);
    IInputerDataImpl inputerDataImpl(1, allInOnePtr);
    int32_t authSubType = 10000;
    EXPECT_NO_THROW(inputerDataImpl.OnSetData(authSubType, data, 0, 0));
}

HWTEST_F(ServicesInputerDataImplTest, ServicesInputerDataImplEnrollTest002, TestSize.Level0)
{
    auto allInOneProxy = new (std::nothrow) MockIAllInOneExecutor();
    ASSERT_TRUE(allInOneProxy != nullptr);
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    std::shared_ptr<PinAuthAllInOneHdi> allInOnePtr = std::make_shared<PinAuthAllInOneHdi>(allInOneProxy);
    IInputerDataImpl inputerDataImpl(1, allInOnePtr);
    int32_t authSubType = 10000;
    EXPECT_NO_THROW(inputerDataImpl.OnSetData(authSubType, data, 0, 0));
}

HWTEST_F(ServicesInputerDataImplTest, ServicesInputerDataImplEnrollTest003, TestSize.Level0)
{
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    auto collectProxy = new (std::nothrow) MockICollectorExecutor();
    ASSERT_TRUE(collectProxy != nullptr);
    std::shared_ptr<PinAuthCollectorHdi> collectorPtr = std::make_shared<PinAuthCollectorHdi>(collectProxy);
    IInputerDataImpl collectInputerDataImpl(1, collectorPtr);
    int32_t authSubType = 10000;
    EXPECT_NO_THROW(collectInputerDataImpl.OnSetData(authSubType, data, 0, 0));
}

HWTEST_F(ServicesInputerDataImplTest, ServicesInputerDataImplEnrollTest004, TestSize.Level0)
{
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    auto collectProxy = new (std::nothrow) MockICollectorExecutor();
    ASSERT_TRUE(collectProxy != nullptr);
    std::shared_ptr<PinAuthCollectorHdi> collectorPtr = std::make_shared<PinAuthCollectorHdi>(collectProxy);
    IInputerDataImpl *collectInputerDataImpl = new IInputerDataImpl(1, collectorPtr);
    EXPECT_NO_THROW(delete collectInputerDataImpl);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
