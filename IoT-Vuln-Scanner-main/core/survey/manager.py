import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List


class SurveyManager:
    def __init__(self, db_path: str = "data/surveys.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """初始化问卷数据库"""
        Path(self.db_path).parent.mkdir(exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 问卷结果表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS survey_responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                survey_type TEXT NOT NULL,  -- 'pre' 或 'post'
                user_id TEXT,
                responses TEXT,  -- JSON格式
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed BOOLEAN DEFAULT 0
            )
        ''')

        # 用户问卷状态表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_survey_status (
                user_id TEXT PRIMARY KEY,
                pre_completed BOOLEAN DEFAULT 0,
                pre_completed_at TIMESTAMP,
                post_completed BOOLEAN DEFAULT 0,
                post_completed_at TIMESTAMP,
                skip_pre BOOLEAN DEFAULT 0
            )
        ''')

        conn.commit()
        conn.close()

    def load_survey(self, survey_type: str) -> str:
        """加载问卷Markdown文件"""
        file_map = {
            'pre': 'ui/surveys/notice_and_choice_pre_survey.md',
            'post': 'ui/surveys/notice_and_choice_post_survey.md'
        }

        filepath = file_map.get(survey_type)
        if not filepath or not Path(filepath).exists():
            raise FileNotFoundError(f"问卷文件不存在: {filepath}")

        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()

    def save_response(self, survey_type: str, responses: Dict, user_id: str = "anonymous"):
        """保存问卷答案"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 保存答案
        cursor.execute('''
            INSERT INTO survey_responses (survey_type, user_id, responses, completed)
            VALUES (?, ?, ?, 1)
        ''', (survey_type, user_id, json.dumps(responses, ensure_ascii=False)))

        # 更新用户状态
        now = datetime.now().isoformat()
        if survey_type == 'pre':
            cursor.execute('''
                INSERT OR REPLACE INTO user_survey_status 
                (user_id, pre_completed, pre_completed_at)
                VALUES (?, 1, ?)
            ''', (user_id, now))
        else:
            cursor.execute('''
                INSERT OR REPLACE INTO user_survey_status 
                (user_id, post_completed, post_completed_at)
                VALUES (?, 1, ?)
            ''', (user_id, now))

        conn.commit()
        conn.close()

    def check_status(self, user_id: str = "anonymous") -> Dict:
        """检查用户问卷状态"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT pre_completed, post_completed, skip_pre 
            FROM user_survey_status 
            WHERE user_id = ?
        ''', (user_id,))

        row = cursor.fetchone()
        conn.close()

        if row:
            return {
                'pre_completed': bool(row[0]),
                'post_completed': bool(row[1]),
                'skip_pre': bool(row[2])
            }
        return {'pre_completed': False, 'post_completed': False, 'skip_pre': False}

    def skip_pre_survey(self, user_id: str = "anonymous"):
        """跳过预调查"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO user_survey_status (user_id, skip_pre)
            VALUES (?, 1)
        ''', (user_id,))
        conn.commit()
        conn.close()