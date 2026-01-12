"""日志分析视图"""
from flask import Blueprint, render_template, request

bp = Blueprint('logs', __name__)

@bp.route('/')
def list_logs():
    page = request.args.get('page', 1, type=int)

    logs = [
        {
            'id': i,
            'timestamp': f'2026-01-12 10:{i:02d}:00',
            'hostname': f'Server-{i % 3 + 1}',
            'level': ['INFO', 'WARNING', 'ERROR'][i % 3],
            'event_id': f'462{i % 5}',
            'message': f'Sample log message {i}'
        }
        for i in range(1, 21)
    ]

    return render_template('logs.html', logs=logs, page=page)

@bp.route('/<int:log_id>')
def detail(log_id):
    log = {
        'id': log_id,
        'timestamp': '2026-01-12 10:30:00',
        'hostname': 'Server-1',
        'level': 'WARNING',
        'event_id': '4624',
        'message': 'User login detected',
        'raw_log': '4624...'
    }
    return render_template('log_detail.html', log=log)