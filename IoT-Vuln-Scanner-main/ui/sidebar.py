# ui/sidebar.py
from flask import Blueprint, render_template

sidebar_bp = Blueprint('sidebar_bp', __name__)

@sidebar_bp.route('/sidebar')
def sidebar():
    return render_template('sidebar.html')
