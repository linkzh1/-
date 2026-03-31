# core\storage\json_to_sql.py
"""
JSON与SQL数据格式转换器
"""
import json
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


class JsonToSqlConverter:
    def __init__(self):
        self.type_mapping = {
            'str': 'TEXT',
            'int': 'INTEGER',
            'float': 'REAL',
            'bool': 'INTEGER',
            'list': 'TEXT',  # JSON存储
            'dict': 'TEXT'  # JSON存储
        }

    def convert_json_to_sql(self, json_data: List[Dict],
                            table_name: str) -> str:
        """生成CREATE TABLE和INSERT语句"""
        if not json_data:
            return ""

        # 推断Schema
        schema = {}
        for item in json_data:
            for key, value in item.items():
                py_type = type(value).__name__
                sql_type = self.type_mapping.get(py_type, 'TEXT')
                schema[key] = sql_type

        # 生成CREATE TABLE
        columns = [f"{k} {v}" for k, v in schema.items()]
        create_sql = f"CREATE TABLE IF NOT EXISTS {table_name} (\n"
        create_sql += ",\n".join(columns)
        create_sql += "\n);"

        # 生成INSERT语句
        insert_sql = f"INSERT INTO {table_name} ({', '.join(schema.keys())}) VALUES "
        values_list = []

        for item in json_data:
            values = []
            for key in schema.keys():
                val = item.get(key)
                if isinstance(val, (list, dict)):
                    val = json.dumps(val, ensure_ascii=False)
                if isinstance(val, str):
                    val = val.replace("'", "''")
                    values.append(f"'{val}'")
                elif val is None:
                    values.append('NULL')
                elif isinstance(val, bool):
                    values.append('1' if val else '0')
                else:
                    values.append(str(val))
            values_list.append(f"({', '.join(values)})")

        insert_sql += ",\n".join(values_list) + ";"

        return create_sql + "\n\n" + insert_sql

    def convert_sql_to_json(self, rows: List, columns: List[str]) -> List[Dict]:
        """将SQL查询结果转换为JSON"""
        result = []
        for row in rows:
            item = {}
            for i, col in enumerate(columns):
                value = row[i] if isinstance(row, (list, tuple)) else getattr(row, col)
                # 尝试解析JSON字符串
                if isinstance(value, str) and (value.startswith('{') or value.startswith('[')):
                    try:
                        value = json.loads(value)
                    except:
                        pass
                item[col] = value
            result.append(item)
        return result