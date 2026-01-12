from flask import Flask,request,session,redirect

def auth():
    # print('拦截器')
    # print(request.path)
    if request.path.startswith('/static'):
        # 继续向后执行，不拦截
        return

    if request.path.startswith('/main'):
        # 继续向后执行，不拦截
        return

    if request.path.startswith('/register'):
        # 继续向后执行，不拦截
        return

    if request.path == '/login':
        # 继续向后执行，不拦截
        return

    user_info = session.get('user_info')
    if user_info:
        # 继续向后执行，不拦截
        # print("通过拦截器的用户的数据：",user_info)
        return

    return redirect('/main')

def get_real_name():
    user_info = session.get('user_info')
    return user_info['real_name']

def create_app():
    app=Flask(__name__)
    app.secret_key="sdfsdfsdfsfs"

    from .views import main
    # 注册蓝图,把main蓝图注册到app中
    app.register_blueprint(main.main_bp)


    return app