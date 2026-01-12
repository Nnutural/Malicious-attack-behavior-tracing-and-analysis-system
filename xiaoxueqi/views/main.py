"""主页视图"""
from flask import Blueprint, render_template

bp = Blueprint('main', __name__)

@bp.route('/')
def index(): # 在模板文件的url_for('main.index')就是指向这个函数（这一个视图的这个函数）
    return render_template('index.html')