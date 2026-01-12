#!/bin/bash

echo -e "\033[1;31m[*] 开始执行真实攻防演示 (Safe Mode)...\033[0m"
echo -e "\033[1;33m[*] 目标: 触发 Falco 内核监控 -> Python 引擎实时分析\033[0m\n"

# 1. 真实触发: 内存注入 (Ptrace)
# 原理: strace 使用 ptrace 系统调用跟踪进程，这是调试行为，也是注入行为
echo "[1/7] 正在模拟: 代码注入 (Ptrace)..."
sudo strace ls > /dev/null 2>&1
sleep 2

# 2. 真实触发: 无文件攻击 (Pipe Execution)
# 原理: 通过管道直接传给 bash 执行，不落地文件，Falco 规则 "Shell only reads stdin"
echo "[2/7] 正在模拟: 无文件执行 (Fileless)..."
echo "echo 'Fileless payload executed'" | /bin/bash
sleep 2

# 3. 真实触发: 文件删除 (痕迹清除)
# 原理: 先创建一个无用的假日志，然后删除它
echo "[3/7] 正在模拟: 痕迹清除 (File Delete)..."
sudo touch /var/log/fake_hack_trace.log
sudo rm /var/log/fake_hack_trace.log
sleep 2

# 4. 真实触发: 文件篡改 (修改配置)
# 原理: 修改 /etc/ 下的文件通常被视为篡改。我们只 touch 一下假文件，不破坏真配置。
echo "[4/7] 正在模拟: 配置篡改 (File Modify)..."
sudo touch /etc/fake_config.conf
# 写入一点数据触发 write
sudo sh -c 'echo "hacked=true" > /etc/fake_config.conf'
sleep 2

# 5. 真实触发: Webshell 落地 (文件创建)
# 原理: 向 /usr/bin/ 或 Web 目录写入文件。Falco 规则 "Write below binary dir"
echo "[5/7] 正在模拟: Webshell 落地 (File Create)..."
sudo touch /usr/bin/fake_webshell_test
sleep 2

# 6. 真实触发: 敏感文件读取
# 原理: 读取 shadow 文件，这是最高危的读取行为
echo "[6/7] 正在模拟: 敏感文件读取 (File Read)..."
sudo cat /etc/shadow > /dev/null
sleep 2

# 7. 真实触发: 网络连接 / 异常进程链
# 原理: 使用 nc 监听端口，或者 python 启动 shell。
# 注意: 为了触发 host_monitor 的 "cmd->powershell" 规则需要修改 monitor 代码
# 这里我们触发一个通用的 "Linux 异常 Shell" (Python 启动 Bash)
echo "[7/7] 正在模拟: 异常进程链/网络连接..."
# 模拟 Python 派生 Shell (常见的提权手法)
python3 -c 'import os; os.system("/bin/ls")'
# 或者尝试建立一个网络连接 (如果安装了 nc)
nc -z 8.8.8.8 53 > /dev/null 2>&1

echo -e "\n\033[1;32m[*] 演示结束! 请检查 host_monitor.py 的输出。\033[0m"
# 清理刚才创建的垃圾文件
sudo rm -f /etc/fake_config.conf /usr/bin/fake_webshell_test
