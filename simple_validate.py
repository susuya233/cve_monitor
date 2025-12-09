#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
简单验证GitHub Workflow配置文件语法
"""

import yaml
import os

def simple_validate():
    """
    简单验证GitHub Workflow配置文件语法
    """
    workflow_file = '.github/workflows/cve_monitor.yml'
    
    if not os.path.exists(workflow_file):
        print("❌ Workflow文件不存在")
        return False
    
    try:
        with open(workflow_file, 'r', encoding='utf-8') as f:
            content = f.read()
            print(f"✅ 读取文件成功，大小: {len(content)} 字节")
            
        # 验证YAML语法
        data = yaml.safe_load(content)
        print("✅ YAML语法正确！")
        
        # 显示基本结构
        print(f"📋 工作流名称: {data.get('name')}")
        print(f"🔧 触发条件: {list(data.get(True, {}).keys()) if True in data else list(data.get('on', {}).keys())}")
        print(f"💼 作业数量: {len(data.get('jobs', {}))}")
        
        return True
    except yaml.YAMLError as e:
        print(f"❌ YAML语法错误: {e}")
        return False
    except Exception as e:
        print(f"❌ 验证失败: {e}")
        return False

if __name__ == '__main__':
    simple_validate()
