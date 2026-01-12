"""仪表盘视图"""
from flask import Blueprint, render_template

bp = Blueprint('dashboard', __name__)

@bp.route('/')
def index():
    stats = {
        'log_count': 1234,
        'process_count': 567,
        'flow_count': 8901,
        'attack_count': 23
    }
    return render_template('dashboard.html', stats=stats)