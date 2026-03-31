import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Question:
    id: str
    text: str
    type: str  # 'single', 'multiple', 'text', 'scale'
    options: List[str]
    required: bool = False


class SurveyParser:
    def __init__(self, md_content: str):
        self.content = md_content
        self.questions = []

    def parse(self) -> List[Question]:
        """解析Markdown格式问卷"""
        lines = self.content.split('\n')
        current_q = None

        for line in lines:
            line = line.strip()

            # 匹配标题（## 或 ###）
            if line.startswith('## ') or line.startswith('### '):
                if current_q:
                    self.questions.append(current_q)
                q_text = line.replace('## ', '').replace('### ', '').strip()
                current_q = {
                    'text': q_text,
                    'options': [],
                    'type': 'text',  # 默认文本
                    'required': '*' in q_text or '必填' in q_text
                }

            # 匹配选项 (- [ ] 或 1. )
            elif line.startswith('- [ ]') or line.startswith('- [x]'):
                if current_q:
                    opt_text = line.replace('- [ ]', '').replace('- [x]', '').strip()
                    current_q['options'].append(opt_text)
                    current_q['type'] = 'multiple' if len(current_q['options']) > 0 else 'text'

            elif re.match(r'^\d+\.', line):
                if current_q:
                    opt_text = re.sub(r'^\d+\.\s*', '', line).strip()
                    current_q['options'].append(opt_text)
                    current_q['type'] = 'single'

            # 匹配量表 (1-5星)
            elif '⭐' in line or '星' in line:
                if current_q:
                    current_q['type'] = 'scale'
                    current_q['options'] = ['1', '2', '3', '4', '5']

        if current_q:
            self.questions.append(current_q)

        # 转换为Question对象
        return [Question(
            id=f"q_{i}",
            text=q['text'],
            type=q['type'],
            options=q['options'],
            required=q['required']
        ) for i, q in enumerate(self.questions)]