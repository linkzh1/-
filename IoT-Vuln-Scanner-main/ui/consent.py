# ui/consent.py

from flask import Blueprint, render_template, request, redirect

consent_bp = Blueprint('consent_bp', __name__)

@consent_bp.route('/consent', methods=['GET'])
def consent():
    return render_template('consent.html')

@consent_bp.route('/save_consent', methods=['POST'])
def save_consent():
    consent = request.form.get('consent')
    # Save consent status (this can be to a file, database, etc.)
    with open('consent_status.txt', 'w') as file:
        file.write(consent)
    return redirect('/')
