from xiaoxueqi import create_app

app=create_app()

if __name__ == '__main__':
    # 关键：use_reloader=False，避免抓包线程被 reloader 重启杀掉
    # 演示/测试抓包时建议关闭 debug，避免调试器/多线程奇怪行为导致退出
    app.run(debug=False, use_reloader=False, host='0.0.0.0', port=5000)