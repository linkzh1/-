# template.py
from flask import render_template

def render_custom_template(template_name, **context):
    return render_template(template_name, **context)
