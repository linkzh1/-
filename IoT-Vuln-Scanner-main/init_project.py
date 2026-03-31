# init_project.py
import os


def init_directories():
    """初始化项目目录结构"""
    dirs = ['logs', 'reports', 'backups', 'data', 'config']
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        # 创建 .gitkeep 确保空目录能被 git 跟踪（如果你用 git）
        open(f"{d}/.gitkeep", 'a').close()

    # 创建 .gitignore 排除日志和备份（避免提交大文件）
    gitignore_content = """
# 项目生成文件
logs/*.log
reports/*.html
reports/*.json
backups/*.db
backups/*.zip
data/*.db
__pycache__/
*.pyc
.env
"""
    with open('.gitignore', 'w') as f:
        f.write(gitignore_content.strip())

    print("✅ 项目目录初始化完成")
    print("📁 logs/    - 运行日志")
    print("📁 reports/ - 扫描报告")
    print("📁 backups/ - 数据备份")


if __name__ == '__main__':
    init_directories()