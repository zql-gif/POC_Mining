### 重要链接
#### tree-sitter
* [python环境解析任意编程语言 tree-sitter使用方法（1）](https://blog.csdn.net/qq_38808667/article/details/128052617?ops_request_misc=&request_id=&biz_id=102&utm_term=tree-sitter%E8%A7%A3%E6%9E%90java&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduweb~default-3-128052617.142^v99^pc_search_result_base7&spm=1018.2226.3001.4187) 
* [python环境解析任意编程语言 tree-sitter使用方法（2）_tree_sitter 解析python](https://blog.csdn.net/qq_38808667/article/details/128172301)
* [利用python和Tree-sitter 提取C++代码中的函数](https://blog.csdn.net/qq_41938789/article/details/125738584?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522170998887516800188588433%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fall.%2522%257D&request_id=170998887516800188588433&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~first_rank_ecpm_v1~rank_v31_ecpm-8-125738584-null-null.142^v99^pc_search_result_base7&utm_term=tree-sitter%E8%A7%A3%E6%9E%90java&spm=1018.2226.3001.4187)
* [基于tree-sitter库提取java文件的所有函数-(icode.best)](https://icode.best/i/60528243823379)
#### javalang
* 获取方法签名：[python脚本寻找Java文件方法_python java parser 库和 javalang](https://blog.csdn.net/qq_27963509/article/details/130143012?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522170978983216800227463299%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fall.%2522%257D&request_id=170978983216800227463299&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~first_rank_ecpm_v1~rank_v31_ecpm-1-130143012-null-null.142^v99^pc_search_result_base7&utm_term=javalang%E5%BA%93%E8%8E%B7%E5%8F%96%E6%96%B9%E6%B3%95%E4%BD%93&spm=1018.2226.3001.4187)


### 语法树的节点属性

```
#通过debugger，可以查看语法树节点的属性（指root_node下的节点）  
# 孩子节点【节点数、节点列表】  
root_node.child_count: int  
root_node.children: list[Node]| None  
  
# 该语法树节点对应代码字符串位置【左闭右开】  
root_node.start_byte: int  
root_node.end_byte: int  
  
# 语法树节点对应代码 (行, 列) 位置元组  
root_node.start_point: tuple[int, int]  
root_node.end_point: tuple[int, int]  
  
'''  
以上的行、列以及字符串位置都是以0开始  
'''  
  
# 语法树命名节点、命名类型 以及 语法树对应的文本  
# 因为具体语法树有代码所有的标记，所以一些符号可能没有类型  
# 我猜测该属性可以用于区别具体语法树符号节点，构建抽象语法树  
root_node.is_named: bool  
root_node.type: str # 没有类型时，这里显示代码原始标记  
root_node.text: bytes  
  
# 语法树父节点  
root_node.parent: Node| None  
  
# 语法树左兄弟、左命名兄弟  
root_node.prev_sibling: Node| None  
root_node.prev_named_sibling: Node| None  
  
  
# 语法树右兄弟、右命名兄弟  
root_node.next_sibling: Node| None  
root_node.next_named_sibling: Node| None



"""  
node_childs[i].type包括：  
1.package_declaration:b'package com.atyang.mybatisplus.t1;'  
2.import_declaration:b'import com.atyang.mybatisplus.strategy.t1.Request;'  
3.block_comment:b'/**  * \xe5\xae\x9a\xe4\xb9\x89\xe8\xaf\xb7\xe6\xb1\x82\xe5\xa4\x84\xe7\x90\x86\xe5\x99\xa8\xe6\x8a\xbd\xe8\xb1\xa1\xe7\xb1\xbb  * @author   */'
4.class_declaration:b''(整个类代码)  
5.modifiers:b'public abstract'  
6.class:b'class'  
7.identifier:b'RequestHandler'  
8.class_body:b''(类的代码体)  
"""

```


