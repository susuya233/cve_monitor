#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
严格验证GitHub Workflow配置文件的YAML语法
"""

import yaml
import os

# 读取文件并显示详细信息
def validate_yaml():
    """
    严格验证YAML文件，显示详细的错误信息
    """
    workflow_file = '.github/workflows/cve_monitor.yml'
    
    if not os.path.exists(workflow_file):
        print(f"❌ 文件不存在: {workflow_file}")
        return False
    
    print(f"✅ 读取文件: {workflow_file}")
    
    try:
        with open(workflow_file, 'rb') as f:
            content_bytes = f.read()
        
        # 检查文件编码和BOM
        if content_bytes.startswith(b'\xef\xbb\xbf'):
            print("⚠️  文件包含UTF-8 BOM")
            content = content_bytes[3:].decode('utf-8')
        else:
            content = content_bytes.decode('utf-8')
            print("✅ 文件编码: UTF-8 (无BOM)")
        
        # 检查行尾符
        if '\r\n' in content:
            print("⚠️  文件使用Windows行尾符 (CRLF)")
        else:
            print("✅ 文件使用Unix行尾符 (LF)")
        
        # 显示文件内容预览
        print(f"\n=== 文件内容预览 ===")
        lines = content.split('\n')
        for i, line in enumerate(lines[:20]):  # 只显示前20行
            print(f"{i+1:2d}: {repr(line)}")
        if len(lines) > 20:
            print(f"... 共 {len(lines)} 行")
        
        # 严格验证YAML语法
        print(f"\n=== 验证YAML语法 ===")
        
        # 使用yaml.safe_load进行严格验证
        data = yaml.safe_load(content)
        print("✅ YAML语法完全正确！")
        
        # 显示解析结果
        print(f"\n=== 解析结果 ===")
        print(f"📋 类型: {type(data)}")
        print(f"📋 键: {list(data.keys())}")
        
        # 检查各字段
        if 'name' in data:
            print(f"✅ name: {data['name']}")
        
        if 'on' in data:
            print(f"✅ on: {list(data['on'].keys())}")
            if 'schedule' in data['on']:
                for i, schedule in enumerate(data['on']['schedule']):
                    if 'cron' in schedule:
                        print(f"   schedule[{i}].cron: {schedule['cron']}")
        
        if 'jobs' in data:
            print(f"✅ jobs: {list(data['jobs'].keys())}")
            for job_name, job_config in data['jobs'].items():
                print(f"   {job_name}:")
                print(f"      runs-on: {job_config.get('runs-on')}")
                if 'steps' in job_config:
                    print(f"      steps: {len(job_config['steps'])}")
        
        return True
    except yaml.YAMLError as e:
        print(f"❌ YAML语法错误！")
        print(f"📋 错误类型: {type(e).__name__}")
        print(f"📝 错误信息: {e}")
        
        # 显示错误位置
        if hasattr(e, 'problem_mark'):
            mark = e.problem_mark
            print(f"📍 错误位置: 行 {mark.line+1}, 列 {mark.column+1}")
            
            # 显示错误位置附近的内容
            with open(workflow_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            start = max(0, mark.line - 2)
            end = min(len(lines), mark.line + 3)
            print(f"\n=== 错误位置附近内容 ===")
            for i in range(start, end):
                prefix = "👉" if i == mark.line else "  "
                line_content = lines[i].rstrip()
                print(f"{prefix} {i+1:2d}: {repr(line_content)}")
                # 显示错误列位置
                if i == mark.line:
                    print(f"   {' '*(mark.column+4)}^ 错误发生在这里")
        
        return False
    except Exception as e:
        print(f"❌ 验证失败: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    validate_yaml()
