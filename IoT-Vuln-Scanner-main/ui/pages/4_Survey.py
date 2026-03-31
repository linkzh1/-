import streamlit as st
import requests
import json
import re
from pathlib import Path
import sys
import time

sys.path.append(str(Path(__file__).parent.parent.parent))

st.set_page_config(page_title="调查问卷", page_icon="📝", layout="wide")

# 隐藏默认的英文侧边栏导航
st.markdown("""
<style>
    [data-testid="stSidebarNav"] {
        display: none !important;
    }
</style>
""", unsafe_allow_html=True)

# 侧边栏中文导航
with st.sidebar:
    st.markdown("### 🧭 功能导航")
    st.page_link("app.py", label="🏠 首页", icon="🏠")
    st.page_link("pages/1_Overview.py", label="📊 网络概览", icon="📊")
    st.page_link("pages/2_Device_Details.py", label="💻 设备详情", icon="💻")
    st.page_link("pages/3_Settings.py", label="⚙️ 系统设置", icon="⚙️")
    st.page_link("pages/4_Survey.py", label="📝 问卷", icon="📝", disabled=True)
    st.divider()
    st.caption("🔄 当前页面：问卷")


def parse_survey_v2(md_content: str):
    sections = []
    current_section = None
    lines = md_content.split('\n')
    i = 0

    while i < len(lines):
        line = lines[i].rstrip()

        if not line or line == '---':
            i += 1
            continue

        if (line.startswith('# ') or line.startswith('## ')) and not line.startswith('### '):
            i += 1
            continue

        if line.startswith('### '):
            if current_section:
                sections.append(current_section)

            title_raw = line.replace('### ', '').strip()

            icon = ''
            title = title_raw
            if title_raw and ord(title_raw[0]) > 127:
                icon = title_raw[0]
                title = title_raw[1:].strip()

            current_section = {
                'icon': icon or '🔹',
                'title': title,
                'type': 'text',
                'options': [],
                'description': '',
                'scale_labels': {'min': '非常不满意', 'max': '非常满意'}
            }

            lookahead = []
            for j in range(1, 4):
                if i + j < len(lines):
                    lookahead.append(lines[i + j].strip())

            for next_line in lookahead:
                if not next_line:
                    continue

                if next_line.startswith('- [ ]') or next_line.startswith('- [x]'):
                    current_section['type'] = 'multiple'
                    break
                elif re.match(r'^\d+\.', next_line):
                    current_section['type'] = 'single'
                    break
                elif '__SCALE__' in next_line:
                    current_section['type'] = 'scale'
                    if '1星' in next_line and '5星' in next_line:
                        parts = next_line.split('，')
                        for part in parts:
                            if '=' in part:
                                kv = part.split('=')
                                if len(kv) == 2:
                                    key, val = kv[0].strip(), kv[1].strip()
                                    if '1' in key:
                                        current_section['scale_labels']['min'] = val
                                    elif '5' in key:
                                        current_section['scale_labels']['max'] = val
                    i += 1
                    break
                elif '__TEXT__' in next_line:
                    current_section['type'] = 'text'
                    i += 1
                    break

        elif line.startswith('- [ ]') or line.startswith('- [x]'):
            if current_section and current_section['type'] == 'multiple':
                opt = line.replace('- [ ]', '').replace('- [x]', '').strip()
                if opt:
                    current_section['options'].append(opt)

        elif re.match(r'^\d+\.', line) and current_section and current_section['type'] == 'single':
            opt = re.sub(r'^\d+\.\s*', '', line).strip()
            if opt:
                current_section['options'].append(opt)

        elif line.startswith('- ') and current_section:
            desc_text = line.replace('- ', '').strip()
            if current_section['type'] == 'text' and not current_section['options']:
                current_section['description'] = desc_text

        i += 1

    if current_section:
        sections.append(current_section)

    return sections


def load_survey(survey_type: str):
    file_map = {
        'pre': 'ui/surveys/notice_and_choice_pre_survey.md',
        'post': 'ui/surveys/notice_and_choice_post_survey.md'
    }

    filepath = file_map.get(survey_type)
    if not filepath or not Path(filepath).exists():
        st.error(f"找不到文件: {filepath}")
        return None

    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()


def submit_to_flask(survey_type: str, responses: dict):
    try:
        processed = {}
        for k, v in responses.items():
            if isinstance(v, list):
                processed[k] = ','.join(v)
            else:
                processed[k] = str(v)

        response = requests.post(
            f"http://localhost:5000/submit_survey/{survey_type}",
            data=processed,
            timeout=5
        )
        return response.ok
    except Exception as e:
        st.error(f"连接后端失败: {e}")
        return False


with st.sidebar:
    st.title("📋 调查问卷")
    survey_type = st.radio(
        "选择问卷类型",
        ["使用前调查", "使用后调查"],
        format_func=lambda x: "🆕 首次使用调查" if x == "使用前调查" else "💬 使用体验反馈"
    )
    type_key = 'pre' if survey_type == "使用前调查" else 'post'

    st.divider()
    st.caption("📊 填写进度")
    progress_text = st.empty()

st.title(f"{'🆕' if type_key == 'pre' else '💬'} {survey_type}")

md_content = load_survey(type_key)
if not md_content:
    st.error("❌ 问卷加载失败")
    st.stop()

sections = parse_survey_v2(md_content)

if not sections:
    st.warning("⚠️ 未能解析到有效问题")
    st.stop()

st.info("💡 请根据您的实际情况填写以下问卷，预计耗时 2 分钟。您的反馈将帮助我们持续改进产品。")

responses = {}
total_questions = len(sections)

with st.form("survey_form"):
    for idx, section in enumerate(sections):
        icon = section['icon']
        title = section['title']
        q_type = section['type']
        options = section['options']
        desc = section.get('description', '')

        progress_text.progress((idx) / total_questions, text=f"问题 {idx + 1}/{total_questions}")

        with st.container():
            cols = st.columns([0.05, 0.95])
            with cols[0]:
                st.markdown(f"### {icon}")
            with cols[1]:
                st.markdown(f"**{title}**")
                if desc:
                    st.caption(f"💡 {desc}")

            q_key = f"q_{idx}"

            if q_type == 'single' and options:
                responses[q_key] = st.radio(
                    label="single_choice",
                    options=options,
                    key=q_key,
                    label_visibility="collapsed",
                    index=None
                )

            elif q_type == 'multiple' and options:
                responses[q_key] = st.multiselect(
                    label="multi_choice",
                    options=options,
                    key=q_key,
                    label_visibility="collapsed",
                    placeholder="请选择（可多选）"
                )

            elif q_type == 'scale':
                labels = section.get('scale_labels', {})
                col1, col2, col3 = st.columns([1, 3, 1])
                with col1:
                    st.caption(labels.get('min', '1星'))
                with col2:
                    responses[q_key] = st.slider(
                        label="scale",
                        min_value=1,
                        max_value=5,
                        value=3,
                        key=q_key,
                        label_visibility="collapsed"
                    )
                    stars = "⭐" * responses.get(q_key, 3)
                    st.caption(stars)
                with col3:
                    st.caption(labels.get('max', '5星'))

            else:
                responses[q_key] = st.text_area(
                    label="text_input",
                    placeholder="请输入您的回答...",
                    key=q_key,
                    label_visibility="collapsed",
                    height=100
                )

            st.divider()

    col_submit, col_skip = st.columns([1, 1])
    with col_submit:
        submitted = st.form_submit_button("✅ 提交问卷", use_container_width=True, type="primary")
    with col_skip:
        skipped = st.form_submit_button("⏭️ 跳过此步骤", use_container_width=True)

if submitted:
    missing = []
    for idx, section in enumerate(sections):
        q_key = f"q_{idx}"
        val = responses.get(q_key)
        if val is None or val == "" or val == []:
            if section['type'] in ['single', 'scale', 'text']:
                missing.append(section['title'])

    if missing:
        st.error(f"❌ 请回答以下必填项：{', '.join(missing[:3])}{'...' if len(missing) > 3 else ''}")
    else:
        with st.spinner("正在保存..."):
            if submit_to_flask(type_key, responses):
                st.success("🎉 感谢您的参与！问卷已成功提交。")
                st.balloons()
                time.sleep(2)
                st.switch_page("pages/1_Overview.py")
            else:
                st.error("❌ 提交失败，请稍后重试。")

if skipped:
    st.warning("⏭️ 您已选择跳过问卷")
    if type_key == 'pre':
        try:
            requests.post("http://localhost:5000/survey/skip_pre", timeout=2)
        except:
            pass

    time.sleep(1)
    st.switch_page("pages/1_Overview.py")