# core\utils\filter_vulnerabilities.py
"""
漏洞过滤器
支持多维度筛选
"""
from typing import List, Dict, Callable, Optional


class VulnerabilityFilter:
    def __init__(self):
        self.filters: List[Callable] = []

    def by_severity(self, min_level: str = 'Medium'):
        """按严重等级过滤"""
        levels = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
        min_val = levels.get(min_level, 0)

        def filter_fn(vulns):
            return [v for v in vulns if levels.get(v.get('severity'), 0) >= min_val]

        self.filters.append(filter_fn)
        return self

    def by_status(self, status: str = 'open'):
        """按状态过滤"""

        def filter_fn(vulns):
            return [v for v in vulns if v.get('status') == status]

        self.filters.append(filter_fn)
        return self

    def by_keyword(self, keyword: str):
        """关键词搜索"""

        def filter_fn(vulns):
            kw = keyword.lower()
            return [
                v for v in vulns
                if kw in v.get('title', '').lower()
                   or kw in v.get('description', '').lower()
                   or kw in v.get('cve_id', '').lower()
            ]

        self.filters.append(filter_fn)
        return self

    def apply(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """应用所有过滤器"""
        result = vulnerabilities
        for f in self.filters:
            result = f(result)
        return result

    @staticmethod
    def deduplicate(vulns: List[Dict]) -> List[Dict]:
        """去重"""
        seen = set()
        unique = []
        for v in vulns:
            cve = v.get('cve_id')
            if cve and cve not in seen:
                seen.add(cve)
                unique.append(v)
        return unique