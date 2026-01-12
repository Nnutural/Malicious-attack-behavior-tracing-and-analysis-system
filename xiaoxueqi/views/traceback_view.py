"""溯源分析视图"""
from flask import Blueprint, render_template

bp = Blueprint('traceback', __name__)

@bp.route('/')
def index():
    return render_template('traceback.html')