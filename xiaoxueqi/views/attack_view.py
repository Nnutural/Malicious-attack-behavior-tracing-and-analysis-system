"""攻击链分析视图"""
from flask import Blueprint, render_template

bp = Blueprint('attack', __name__)

@bp.route('/')
def index():
    return render_template('attack_chain.html')