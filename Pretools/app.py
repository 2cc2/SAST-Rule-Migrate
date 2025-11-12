import os
import json
from flask import Flask, render_template, request, send_file

app = Flask(__name__)

# 你的JSON数据结构
file_structure = {}
with open('/home/cbb/Pretools/codeql_files_tree_with_imports.json', 'r', encoding='utf-8') as f:
    file_structure = json.load(f)

def get_node_by_path(path):
    """根据路径获取对应的节点"""
    if not path:
        return file_structure
    
    parts = path.split('/')
    current = file_structure
    
    for part in parts:
        if part in current:
            current = current[part]
        else:
            return None
    
    return current

def is_file(node):
    """判断节点是否为文件（有filepath）"""
    return isinstance(node, dict) and "path" in node

def get_file_content(filepath):
    """读取文件内容"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"无法读取文件: {str(e)}"

@app.route('/')
def index():
    """根目录 - 显示顶层结构"""
    return render_template('directory.html', 
                         node=file_structure, 
                         current_path="", 
                         breadcrumbs=[("根目录", "/")])

@app.route('/browse/<path:subpath>')
def browse(subpath):
    """浏览目录或文件"""
    node = get_node_by_path(subpath)
 
    if node is None:
        return "路径不存在", 404
    
    # 构建面包屑导航
    breadcrumbs = [("根目录", "/")]
    path_parts = subpath.split('/')
    for i, part in enumerate(path_parts):
        breadcrumb_path = '/'.join(path_parts[:i+1])
        breadcrumbs.append((part, f"/browse/{breadcrumb_path}"))
    # if "path" in node:
        
    if is_file(node):
        print("*"*8)
        print(node)
        # 显示文件内容
        content = get_file_content(node.get("path"))
        imports = node.get("imports", [])
        imports_text = "\n".join(imports) if isinstance(imports, list) else str(imports)
        return render_template('file.html', 
                             filename=path_parts[-1] if path_parts else subpath,
                             filepath=node,
                             content=content,
                             imports=imports_text,
                             breadcrumbs=breadcrumbs,
                             parent_path='/'.join(path_parts[:-1]) if path_parts else "/")
    else:
        # 显示目录内容
        return render_template('directory.html', 
                             node=node, 
                             current_path=subpath,
                             breadcrumbs=breadcrumbs)
def search_files(query, node=None, current_path=""):
    """在文件结构中搜索文件"""
    results = []
    
    if node is None:
        node = file_structure
    
    for name, item in node.items():
        full_path = f"{current_path}/{name}" if current_path else name
        
        if query.lower() in name.lower():
            results.append({
                'name': name,
                'path': full_path,
                'type': 'file' if is_file(item) else 'folder'
            })
        
        # 递归搜索子目录
        if not is_file(item):
            results.extend(search_files(query, item, full_path))
    
    return results

@app.route('/search')
def search():
    """搜索文件"""
    query = request.args.get('q', '')
    if not query:
        return render_template('search.html', results=[], query=query)
    
    results = search_files(query)
    return render_template('search.html', results=results, query=query)
@app.route('/download/<path:subpath>')
def download(subpath):
    """下载文件"""
    node = get_node_by_path(subpath)
    
    if node is None or not is_file(node):
        return "文件不存在", 404
    
    if os.path.exists(node):
        return send_file(node, as_attachment=True)
    else:
        return "文件不存在", 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)