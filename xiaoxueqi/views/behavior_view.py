"""主机行为分析视图"""
from flask import Blueprint, render_template

bp = Blueprint('behavior', __name__)

@bp.route('/')
def index():
    return render_template('behavior.html')