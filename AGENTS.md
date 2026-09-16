# PIN 认证组件指引

## 项目定位

本仓库对应 OpenHarmony `base/useriam/pin_auth`，是统一用户认证框架（user_auth_framework）配套的 PIN 认证系统能力。优先按这些目录定位问题：

- `services/sa/`：PinAuthService 系统能力生命周期、注册、OnStart/OnStop
- `frameworks/client/`：Inputer 注册、回调管理、PinAuthRegisterImpl
- `frameworks/ipc/`：InputerGetData/InputerSetData 的 IPC Proxy/Stub
- `services/modules/inputters/`：PinAuthManager 输入器管理、IInputerData 数据传输
- `services/modules/driver/`：PinAuthDriverHdi HDI 驱动、PinAuthInterfaceAdapter TEE 适配
- `services/modules/executors/`：CollectorHDI/VerifierHDI/AllInOneHDI 执行器 HDI
- `frameworks/scrypt/`：PIN 数据加密（scrypt 算法）
- `interfaces/inner_api/`：Inner Kit API 定义（IInputer、IInputerData、PinAuthRegister）
- `sa_profile/`：SA 配置（SA ID 941，进程 useriam）
- `test/unittest/`、`test/fuzztest/`：单元测试和 fuzz 目标

### 按任务类型定位代码

| 任务类型 | 首选目录 | 关键文件 |
| --- | --- | --- |
| SA 生命周期、注册、OnStart/OnStop | `services/sa/` | `pin_auth_service.h`, `pin_auth_service.cpp` |
| Inputer 注册、回调管理 | `frameworks/client/` | `pinauth_register_impl.h`, `pinauth_register_impl.cpp`, `inputer_data_impl.cpp` |
| IPC Proxy/Stub 实现 | `frameworks/ipc/` | `inputer_get_data_proxy.cpp`, `inputer_set_data_stub.cpp` |
| 输入器数据传送到 TEE | `services/modules/inputters/` | `pin_auth_manager.cpp`, `i_inputer_data_impl.cpp` |
| HDI 驱动、TEE 适配层 | `services/modules/driver/` | `pin_auth_driver_hdi.cpp`, `pin_auth_interface_adapter.cpp` |
| Collector/Verifier/AllInOne 执行器 HDI | `services/modules/executors/` | `*collectorhdi.cpp`, `*verifierhdi.cpp`, `*allinonehdi.cpp` |
| PIN 数据 scrypt 加密 | `frameworks/scrypt/` | `scrypt.cpp` |
| Inner Kit API 定义 | `interfaces/inner_api/` | `i_inputer.h`, `i_inputer_data.h`, `pinauth_register.h` |
| SA 配置 | `sa_profile/` | `941.json`, `default/941.json` |
| Fuzz 测试 | `test/fuzztest/` | `services/sa/pinauthservice_fuzzer.cpp` |
| 单元测试 | `test/unittest/` | `pin_auth_service_test.cpp` |

### 嵌套指引

本仓库无目录级别的嵌套指引。所有任务级指导已在本文档"知识索引"章节提供，无需额外阅读文档。

## 构建和验证

构建命令从 OpenHarmony 源码根目录执行，不在本子目录执行。

```sh
./build.sh --product-name rk3568 --ccache --build-target pin_auth
```

代码规范检查（C++）：

```sh
clang-tidy -p=out/rk3568 --fix-errors services/sa/*.cpp frameworks/client/*.cpp frameworks/ipc/*.cpp
```

运行单元测试：

```sh
./build.sh --product-name rk3568 -ccache --build-target PinAuth_UT_test
./build.sh --product-name rk3568 -ccache --build-target pin_auth_fuzz_test
```

### 测试任务分发

根据改动类型选择对应测试：

| 改动类型 | 测试目标 | 验证方式 |
| --- | --- | --- |
| SA 生命周期、OnStart/OnStop | `test/unittest/pin_auth_service_test.cpp` | 单元测试，验证 SA 启动/停止流程 |
| Inputer 注册/注销、`registerInputer`/`unregisterInputer` | `test/unittest/` 下的 inputer 相关测试 | 验证回调注册和生命周期管理 |
| IPC Proxy/Stub、消息码 | `frameworks/ipc/` 下的单元测试 | 验证 marshalling/unmarshalling 正确性 |
| HDI 驱动、`PinAuthDriverHdi` | CollectorHdi/VerifierHdi 测试 | 板侧验证 hdc 日志输出 |
| TEE 适配层、`PinAuthInterfaceAdapter` | `test/unittest/` 相关测试 | 结合 hdc shell 日志验证 TEE 通信 |
| PIN 数据加密、scrypt | `test/unittest/` 加密相关测试 | 验证加密结果一致性 |
| 代码规范、C++ 内存安全 | C++ static analysis | `clang-tidy` 或 IDE 内置检查 |
| IDL 生成代码、IPC marshalling | IDL compiler + stub 验证 | 重新编译生成代码并检查 `*_proxy.cpp`/`*_stub.cpp` |
| IPC 消息码同步 | 代码审查 | 确认 `*_ipc_interface_code.h` 与 Proxy/Stub 实现一致 |

### 完成标准

任务被认为完成，当且仅当：

1. **代码改动已提交** - 使用 `git commit -s`，多代理协作时添加 `Co-Authored-By: Agent`
2. **本地构建通过** - 执行上述构建命令，`pin_auth` 目标构建成功，且无 ESLint/C++ static analysis 错误
3. **相关测试通过** - 对应单元测试通过：`//base/useriam/pin_auth/test/unittest:PinAuth_UT_test`
4. **代码规范检查通过** - C++ 代码通过 `clang-tidy` 检查，无内存安全问题
5. **协议兼容性验证** - IPC 消息码、marshalling 顺序与 `*_ipc_interface_code.h` 定义一致；HDI 接口签名未改变
6. **板侧验证（如适用）** - 涉及 HDI/TEE/输入器生命周期的改动需提供板侧证据

### 如果无法运行验证

明确说明无法运行的原因，列出推荐的验证步骤供人工执行，标记需要人工验证的部分。

### 完成报告格式

报告应包含：改动摘要（文件列表、改动点）、验证结果（构建/测试输出）、风险评估（API 兼容性、性能风险）、未完成事项。

## 知识索引

改动前按场景读取对应文件：

### 场景与路径路由

| 场景 | 修改目录 | 先读文档 |
| --- | --- | --- |
| PIN 输入框注册、`registerInputer`/`unregisterInputer`、回调生命周期 | `frameworks/client/` | `pinauth_register_impl.cpp`, `inputer_data_impl.cpp` |
| `IInputer::OnGetData` 获取 PIN、`IInputerData::OnSetData` 回传 PIN | `frameworks/client/`, `interfaces/inner_api/` | `i_inputer.h`, `i_inputer_data.h` |
| IPC 消息码、Proxy/Stub marshalling | `frameworks/ipc/` | `inputer_get_data_ipc_interface_code.h`, `inputer_set_data_ipc_interface_code.h` |
| TEE 通信、PinAuthDriverHdi 调用、InterfaceAdapter | `services/modules/driver/` | `pin_auth_driver_hdi.cpp`, `pin_auth_interface_adapter.cpp` |
| Collector/Verifier/AllInOne 执行器 HDI | `services/modules/executors/` | `services/modules/executors/inc/` 目录下头文件 |
| PinAuthManager 单例、TokenId 管理、DeathRecipient | `services/modules/inputters/` | `pin_auth_manager.cpp` |
| SA 启动、OnStart/OnStop、DriverManager | `services/sa/` | `pin_auth_service.cpp` OnStart/OnStop 章节 |
| 构建、板侧测试、HAP 安装 | 任何构建/测试相关改动 | 参考本文档"构建和验证"章节 |

### 术语与知识入口

遇到以下领域术语时，优先阅读对应文件：

| 领域术语 | 优先阅读 | 原因 |
| --- | --- | --- |
| `TokenId`、`activeUserId` | `pin_auth_manager.cpp` | TokenId 管理、调用方身份标识 |
| `DeathRecipient`、`sptr<>` | `pin_auth_manager.cpp` 第 50-100 行 | 对端崩溃处理、远程对象生命周期管理 |
| `IInputer::OnGetData`、`IInputerData::OnSetData` | `i_inputer.h`, `i_inputer_data.h` | 输入器回调接口定义，PIN 数据传输路径 |
| `registerInputer`、`unregisterInputer` | `pinauth_register_impl.cpp` | Inputer 注册/注销实现 |
| `PinAuthDriverHdi`、`PinAuthInterfaceAdapter` | `pin_auth_driver_hdi.cpp`, `pin_auth_interface_adapter.cpp` | TEE 通信适配层 |
| `CollectorHdi`、`VerifierHdi`、`AllInOneHdi` | `services/modules/executors/inc/` | 执行器 HDI 接口定义 |
| `scrypt`、`N/r/p` 参数 | `scrypt.cpp` | PIN 数据加密算法和参数 |
| `InputerGetData`、`InputerSetData` IPC | `frameworks/ipc/` | IPC 消息码、Proxy/Stub 实现 |
| `PinAuthService::OnStart`、`OnStop` | `pin_auth_service.cpp` | SA 生命周期管理 |
| `MessageParcel`、`ReadInt32/WriteInt32` | `frameworks/ipc/` 或 `services/modules/driver/` | IPC 数据序列化 |

### 开始编辑前

在修改代码前，按以下顺序确认：
1. 确认任务类别（SA 生命周期 / IPC / 输入器管理 / HDI 驱动 / 测试）
2. 根据上表确定需要阅读的文档（若尚未存在，先在本表登记路径再据需要创建）
3. 根据"项目约束"确认不违反任何约束
4. 声明："我将修改 X，已阅读 Y 文档，遵循 Z 约束"

## 项目约束

### 性能约束

- `OnGetData` 回调在认证服务请求 PIN 时触发，避免在其中做耗时的加密操作或大量内存分配。
- `PinAuthManager` 的 `mutex_` 是输入器映射表锁，避免在锁内执行不必要的操作。

### 架构约束

- `PinAuthService` 仅负责 SA 生命周期和输入器协调，业务逻辑在 `frameworks/` 和 `services/modules/` 中。
- `PinAuthManager` 为单例（`DelayedRefSingleton`），通过 `tokenId` 区分不同调用方。
- IPC Proxy/Stub 严格按 `*_ipc_interface_code.h` 中定义的消息码分发，不得混用。
- HDI 调用必须通过 `PinAuthInterfaceAdapter` 适配，不得绕过 TEE 直接传递 PIN 数据。

### 编码约定

- C++ 改动优先复用附近的 `MMI_HILOG*` 项目宏。
- 使用 `sptr<>` 管理远程对象生命周期，DeathRecipient 处理对端崩溃。
- 不要使用 `CHKPV*`、`CHKPR*`、`CHKPC*` 等改变代码逻辑的宏进行指针判空。

### 常见 Agent 失误模式

**必须避免的失误：**
- 在 `OnGetData` 回调中做耗时操作（加密、内存分配）- 应仅获取 PIN 数据并通过 callback 回传
- 使用 `CHKPV*` 等宏改变控制流（正确模式：`if (!ptr) return;`）
- 在锁内执行不必要的操作（`PinAuthManager::mutex_` 保护输入器映射表）
- 修改 IPC 消息码而不同步 `*_ipc_interface_code.h` 中的定义
- 绕过 `PinAuthInterfaceAdapter` 直接调用 HDI 或传递 PIN 数据到 TEE
- 在安全环境外输出或传输 PIN（应仅通过 `IInputerData::OnSetData` 回传 `std::vector<uint8_t>`）

### PIN 数据安全（关键）

**Do not（禁止）：**
- 将 PIN 数据（`std::vector<uint8_t>` 或 `Uint8Array`）写入 hilog 或文件
- 在未加密情况下跨进程传递原始 PIN 数据
- 修改 `IInputerData::OnSetData` 的签名或语义
- 绕过 TEE 存储 - 所有 PIN 比对必须在安全环境中执行
- 在 `IInputer::OnGetData` 回调之外输出或传输 PIN

**Ask before（修改前必须确认）：**
- 修改 `IInputer::OnGetData` 签名
- 改变 PIN 数据从 UI 到 TEE 的流程
- 修改 scrypt 参数（`N`、`r`、`p`）

### 公共 API 约束

**Do not（禁止）：**
- 修改 `PinAuthService::RegisterInputer` 或 `UnRegisterInputer` 签名
- 修改 SA ID（941）或进程名（`useriam`）
- 修改 Inner Kit 头文件（`i_inputer.h`、`i_inputer_data.h`、`pinauth_register.h`）
- 修改 `sa_profile/default/941.json` 配置

**Ask before（修改前必须确认）：**
- 新增 HDI 方法到 `PinAuthDriverHdi`
- 修改 `PinAuthInterfaceAdapter` 与 TEE 的通信协议

### IPC 接口稳定性

**Do not（禁止）：**
- 修改 `InputerGetDataProxy`、`InputerGetDataStub`、`InputerSetDataProxy`、`InputerSetDataStub` 的消息码
- 改变 IPC marshalling/unmarshalling 逻辑
- 为 IPC 回调添加可选参数

### 协议与数据格式兼容性

**Do not（禁止）：**
- 修改 IDL 定义的 IPC 接口签名、Parcel 序列化顺序
- 修改跨进程传递的数据结构布局（如字段顺序）
- 修改已有 HDI 接口的签名或返回值

**Ask before（修改前必须确认）：**
- 新增 IPC 接口：确认是否需要跨版本兼容性处理
- 修改 HDI 接口：确认是否影响设备驱动兼容性

### 生成代码边界

**Do not（禁止）：**
- 直接修改 IDL 编译器生成的 C++ 代码文件
- 手动编辑生成的 IPC Proxy/Stub 代码

**正确做法：**
- 修改 IDL 定义文件（`*.idl`）
- 重新运行 IDL 编译器生成代码
- 如果生成代码不满足需求，考虑调整 IDL 定义或使用回调机制

### 测试代码约束

**Do not（禁止）：**
- Mock `IInputer::OnGetData` 以绕过实际 PIN 数据流程
- 创建使用硬编码 PIN 值就能通过的 UT
- 修改 fuzz 测试模板而不增加新覆盖率

### 设备操作约束

**涉及真实设备时的注意事项：**
- 不执行可能影响设备正常运行的破坏性操作
- 需要在真实设备上验证的改动，必须提供板侧证据（日志、hdc 输出）
- TEE 操作需要确认安全环境可用性

## 关键依赖与外部协同

- **上游**：`useriam_user_auth_framework`（统一用户认证框架）- 通过 HDI 调用 pin_auth
- **下游**：`drivers_peripheral`（TEE 实现）、`drivers_interface_pin_auth`（HDI 定义）
- **SDK**：`@ohos.userIAM.userAuth`（AuthSubType 枚举）
- **权限**：`ACCESS_PIN_AUTH`、`SET_USER_AUTH`
