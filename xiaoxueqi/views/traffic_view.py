"""网络流量分析视图"""
from flask import Blueprint, render_template

bp = Blueprint('traffic', __name__)

@bp.route('/')
def index():
    return render_template('traffic.html')