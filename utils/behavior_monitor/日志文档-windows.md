# windows

https://learn.microsoft.com/zh-cn/sysinternals/downloads/sysmon下载sysmon

https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml下载xml配置文件

管理员该文件夹下运行`.\Sysmon.exe -c .\sysmonconfig-export.xml` 加载配置

```txt
使用

打开事件查看器，或者运行输入eventvwr.msc，

在打开的事件查看器中依次选择应用程序和服务日志>Microsoft>Windows>Sysmon，可以看到记录的事件情况，

    下面是 Sysmon 生成的每种事件类型的示例。

    事件 ID 1：进程创建
    进程创建事件提供有关新创建的进程的扩展信息。 完整命令行提供进程执行的相关上下文。“ProcessGUID”字段是此进程在整个域中的唯一值，能够简化事件关联。哈希是文件的完整哈希，其中包含“HashType”字段中的算法。

    事件 ID 2：进程更改了文件创建时间
    当进程明确修改了文件创建时间时，将注册更改文件创建时间事件。 此事件可帮助跟踪文件的实际创建时间。攻击者可能会更改后门的文件创建时间，使其看起来像是随操作系统一起安装的。请注意，许多进程会合法地更改文件的创建时间，这种行为不一定表示恶意活动。

    事件 ID 3：网络连接
    网络连接事件记录计算机上的 TCP/UDP 连接。 此项默认禁用。 每个连接都通过 ProcessId 和ProcessGuid 字段链接到一个进程。 该事件还包含源和目标主机名 IP 地址、端口号和 IPv6 状态。

    事件 ID 4：Sysmon 服务状态已更改
    服务状态更改事件报告 Sysmon 服务的状态（已启动或已停止）。

    事件 ID 5：进程已终止 进程终止事件报告进程的终止时间。
    它提供进程的 UtcTime、ProcessGuid 和 ProcessId。

    事件 ID 6：驱动程序已加载
    驱动程序已加载事件提供系统上正在加载的驱动程序的相关信息。 会提供已配置的哈希以及签名信息。出于性能，签名以异步方式创建，指示加载后文件是否被删除。

    事件 ID 7：映像已加载
    映像已加载事件记录特定进程中加载某个模块的时间。 此事件默认处于禁用状态，需要使用“–l”选项进行配置。
    它指示模块在哪个进程中加载、哈希，以及签名信息。 出于性能，签名以异步方式创建，指示加载后文件是否被删除。
    应小心配置此事件，因为监视所有映像加载事件会产生大量日志记录。

    事件 ID 8：CreateRemoteThread “CreateRemoteThread”事件检测一个进程在另一个进程中创建线程的时间。
    恶意软件使用这种方法注入代码并隐藏在另一个进程中。 此事件指示源进程和目标进程。
    它提供将会在新线程中运行的代码的相关信息：StartAddress、StartModule 和 StartFunction。
    请注意，StartModule 和 StartFunction
    字段是推断出来的。如果起始地址在加载的模块或已知导出的函数之外，则这两个字段可能为空。

    事件 ID 9：RawAccessRead “RawAccessRead”事件检测进程使用“\.\”本意从驱动器进行读取操作的时间。
    恶意软件通常使用这种方法让已锁定不许读取的文件发生数据泄露，以及避开文件访问审计工具。 此事件指示源进程和目标设备。

    事件 ID 10：ProcessAccess
    已访问进程事件报告一个进程打开另一个进程的时间，一项操作通常后跟信息查询，或读取写入目标进程的地址空间。
    这样就可以检测在哈希传递攻击中为了窃取要使用的凭据，读取本地安全机构 (Lsass.exe) 等进程的内存内容的黑客工具。
    如果有诊断实用工具反复打开进程来查询其状态，则启用此事件会产生大量日志记录。因此，一般而言应该仅使用移除预计的访问的筛选器来完成此操作。

    事件 ID 11：FileCreate 当创建或覆盖文件时，记录文件创建操作。
    此事件可用于监视自动启动位置，例如启动文件夹，以及临时和下载目录，这些是初始感染期间恶意软件会前往的常见位置。

    Event ID 12：RegistryEvent（对象创建和删除）
    注册表项和值创建和删除操作映射到此事件类型，此事件可用于监视对注册表自动启动位置的更改，或特定恶意软件注册表修改。
    Sysmon 使用以下映射的注册表根键名称的缩写版本：
    项名 缩写 HKEY_LOCAL_MACHINE HKLM HKEY_USERS HKU
    HKEY_LOCAL_MACHINE\System\ControlSet00x HKLM\System\CurrentControlSet
    HKEY_LOCAL_MACHINE\Classes HKCR 事件 ID 13：RegistryEvent（值设置）此注册表事件类型识别注册表值修改。 此事件记录为类型 DWORD 和 QWORD 的注册表值写入的值。

    事件 ID 14：RegistryEvent（项和值重命名） 注册表项和值重命名操作映射到此事件类型，记录重命名后的项或值的新名称。

    事件 ID 15：FileCreateStreamHash 此事件记录创建已命名文件流的时间，并且会生成事件来记录将流（未命名的流）分配到的文件中的内容的哈希，以及已命名的流的内容。有的恶意软件变体通过浏览器下载来放置其可执行文件或配置设置，此事件旨在根据浏览器附加 Zone.Identifier“Web标记”流来捕获此类情况。

    事件 ID 16：ServiceConfigurationChange 此事件记录 Sysmon 配置中的更改，例如，更新筛选规则的时间。

    事件 ID 17：PipeEvent（管道已创建） 当创建已命名的管道时生成此事件。 恶意软件通常使用已命名管道进行进程间通信。

    事件 ID 18：PipeEvent（管道已连接） 此事件记录客户端和服务器之间建立已命名管道连接的时间。

    事件 ID 19：WmiEvent（检测到 WmiEventFilter 事件） 注册 WMI事件筛选器时，恶意软件使用此方法来执行攻击，此事件记录 WMI 命名空间、筛选器名称和筛选器表达式。

    事件 ID 20：WmiEvent（检测到 WmiEventConsumer 活动） 此事件记录 WMI使用者的注册，具体会记录使用者姓名、日志和目的地。

    事件 ID 21：WmiEvent（检测到 WmiEventConsumerToFilter 活动）当使用者绑定到某个筛选器时，此事件记录下该使用者的姓名和筛选器路径。

    事件 ID 22：DNSEvent（DNS 查询） 无论结果是成功还是失败、是否会缓存，当进程执行 DNS 查询时都会生成此事件。 已为Windows 8.1 添加了此事件的遥测，因此它在 Windows 7 及更早版本上不可用。

    事件 ID 23：FileDelete（文件删除已存档） 文件已删除。 除了记录此事件，被删除的文件还保存在ArchiveDirectory 中（C:\Sysmon 是默认）。 正常运行的情况下，此目录可能会增长到不合理的大小，请参阅事件 ID
    26：FileDeleteDetected，其行为虽然类似，但是不保存被删除的文件。

    事件 ID 24：ClipboardChange（剪贴板中的新内容） 系统剪贴板内容发生变化时会生成此事件。

    事件 ID 25：ProcessTampering（进程映像更改） 当检测到“空心”或“herpaderp”等进程隐藏手段时会生成此事件。

    事件 ID 26：FileDeleteDetected（文件删除已记录） 文件已删除。

    事件 ID 27：FileBlockExecutable 当 Sysmon 检测并阻止创建可执行文件（PE 格式）时生成此事件。

    事件 ID 28：FileBlockShredding 当 Sysmon 检测并阻止 SDelete 等工具粉碎文件时生成此事件。

    事件 ID 29：FileExecutableDetected 当 Sysmon 检测到新建可执行文件（PE 格式）时生成此事件。

    事件 ID 255：错误 当 Sysmon 中发生错误时生成此事件。 如果系统负载过重且无法执行某些任务或 Sysmon 服务中存在bug，或者即使不满足某些安全和完整性条件，也可能发生这些错误。 
```

加载完成后运行`xdr_launcher.py`自动运行windows主机行为监控函数。