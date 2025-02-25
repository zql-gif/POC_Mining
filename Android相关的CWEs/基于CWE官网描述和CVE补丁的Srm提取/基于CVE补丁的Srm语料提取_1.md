### 思路概述  
#### 基本假设
* patch p位于方法A中
	* patch p增加了对A的返回值的验证：A可能为source方法  
	- patch p删除了某一方法调用B：B以A的参数作为自身参数且B有发送数据/写入数据的含义，则B可能为sink
#### 角度一：被修改的函数
* patch筛选：筛选出被patch修改过的所有方法，并从raw code原代码文件中提取出来
* LLM分析：结合基本假设，利用LLM判断patch所在方法是否为source/sink方法
	* SequentialChain：分步分析多个pathes文件，存储每一个pathch的总结信息
	* Conclusion：综合多个patch文件的总结信息得到最终分析结果（JSON格式）
#### 角度二：被增减的函数
* patch的操作包含增加代码和删减代码
	* 增加代码
	* 删减代码



### 角度一：被修改的函数
#### patch筛选
筛选出patch中被修改过的所有方法，并基于tree-sitter和javalang从raw code中提取对应方法的位置信息。
* 处理diff文件（PatchParser.py）：读取patch修改信息 ，记录下所有文件中的所有修改块。针对单个文件，记录格式如下。（ [diff文件的格式](https://blog.csdn.net/hexf9632/article/details/105488132)）
``` Python
"""  
功能：  
处理patch文件：读取patch内容，字符串匹配（类似：@@ -1609,9 +1628,14 @@）得到所有修改块儿在原始文件的位置信息。  
针对单个patch文件，记录格式为列表。  
  
输入：FinalCommitResults文件夹中的所有json文件  
  
输出：  
结果格式如下，  
 {  "index": 0, 
    "details":[
           {'raw_url':url,diffs':[[1609,9,1628,14],[],……],'patches':["","","",……],'raw_code':""}, 
           {},
           {}    
    ]
}  
  
特别说明：  
1."@@ -1609,9 +1628,14 @@"  含义：原始文件代码块范围：[1609,1609+9),新文件代码块范围：[1628,1628+14)  
"""
```

 * 处理raw_code
	 * 用tree-sitter工具处理raw_code（[[tree-sitter & javalang]]）
	 * RawCodeParser类：遍历diffs和patchs，解析对应的java代码。对于每一对(diff,patch)，dfs搜索定位被修改代码块在raw_code中的node。最后得到(diffs,patchs)对应的节点数组diff_nodes。可以从diff_nodes获取被修改代码块所属节点的全部代码和各种信息。
	 *  ~~废除方案：合并details_raw_code的信息到details_diff中，得到新的details_diff：根据details_diff的diffs和details_raw_code的function_position，得到单个patch文件中被修改的所有函数的下标信息（存储到details_diff的function_changed）。
	 
``` Python
#重写原始代码解析类：
def dfs(self, node,diff_range,node_list):  
    """  
    边界节点：
       父节点为program的非class_declaration的节点（block_comment，import_declaration等）          父节点为class_declaration的非class_body的节点（如modifiers,class,identifier等）,  
       父节点为class_body的非class_declaration且非method_declaration的节点（如field_declaration,line_comment,enum_declaration等）,  
       method_declaration（重要）,
       其他没有子节点的节点    
       
    非边界节点：program,class_declaration,class_body  
  
    1.处理到非边界节点时:  
    若node_end<diff_start（无交集）,放弃该节点，返回；  
    若有交集，递归处理该节点的所有子节点；    
    若diff_end<node_start（无交集），从左往右的分析已经完成，应该退出返回。  
  
    2.处理到边界节点时:  
    需要判断diff_range是否和该边界节点有交集，  
    如果有交集则将该边界节点存储到node_list中,并返回；没有交集则返回。  
    """  
    diff_start=diff_range[0]  
    diff_end=diff_range[1]  
    node_start=node.start_point[0]  
    node_end=node.end_point[0]  
    node_childs = node.children  
  
    #边界节点：需要判断diff_range是否和该边界节点有交集，如果有交集则将该边界节点存储到node_list中,并返回；没有交集则返回。  
    if self.isEnd(node):  
        if self.isCrossed(diff_start,diff_end,node_start,node_end):  
            node_list.append(node)  
        return  
        
    #非边界节点:若node_end<diff_start（无交集）,放弃该节点，返回；若有交集，递归处理该节点的所有子节点；若diff_end<node_start（无交集），从左往右的分析已经完成，应该退出返回。  
    if self.isCrossed(diff_start, diff_end, node_start, node_end) ==0 :  
        return  
    else:  
        # 若有交集，递归处理该节点的所有子节点；  
        for i in range(len(node_childs)):  
            self.dfs(node_childs[i], diff_range, node_list)  
  
  
#解析单条detail_diff：基于dfs遍历算法解析单条detail_diff中的raw_code,得到所有方法对应的节点method_nodes。  
def Parser(self,diff_range):  

#遍历diffs和patchs，对于每一对(diff,patch)，定位被修改代码块在raw_code中的node。最后得到(diffs,patchs)对应的节点数组diff_nodes  
def Get_Diff_Nodes(self):  
        
```

* 其他：暂时根据”@@ -1609,9 +1628,14 @@“确定被修改范围，其实这部分范围略大于真实修改范围。后续考虑增加功能来提取+和-的函数。
  ![[Pasted image 20240312020927.png]]


#### LLM分析
##### 总体设计
* LLM分析：**针对不同CWE类型**，利用LLM判断patch所在方法是否为source/sink/sanitizer方法
	* SequentialChain：分步分析多个pathes文件，存储每一个pathch的总结信息
	* Conclusion：综合多个patch文件的总结信息得到最终分析结果（JSON格式）
##### CWE选型
[[数据爬取-与Android相关的CWEs#3.CVE官网列出的和Android相关的CVEs]]

```
选择的CWE范围（同时满足：2014-2023年Android报告的高频CWE，论文提到与Android相关的CWE，与污点强相关的CWE）

types = ["CodeException", "Bypass", "PrivilegeEscalation", "DenialOfService", "InformationLeak"]

Java相关的共计205条，C/C++相关的共计238条；共计443条
('CWE-200', 0.10135869565217391)  #Information exposure(all:134(0,0,3,2,129);Java:48(0,0,3,0,45);C/C++:81(0,0,0,2,79))
('CWE-862', 0.09320652173913044)  #Missing authorization(all:57(0,0,5,4,48);Java:49(0,0,2,4,43);C/C++:5(0,0,3,0,2))
('CWE-284', 0.057608695652173914) #Improper access control(all:86(3,33,33,17,0);Java:43(0,18,18,7,0);C/C++:36(3,12,12,9,0))
('CWE-20', 0.05597826086956522)   #Improper input validation(all:114(25,0,5,62,22);Java:39(1,0,1,21,16);C/C++:73(23,0,4,41,5))


('CWE-264', 0.03885869565217391)  #Permissions, privileges, and access control(all:41(20,0,12,9,0);Java:6(2,0,0,4,0);C/C++:32(17,0,10,5,0))
('CWE-287', 0.02309782608695652) #Improper authentic(all:23(0,11,11,0,1);Java:13(0,6,6,0,1);C/C++:10(0,5,5,0,0))
('CWE-276', 0.010869565217391304) #Incorrect default permissions(all:6(0,0,0,0,6);Java:5(0,0,0,0,5);C/C++:0(0,0,0,0,0))
('CWE-668', 0.010054347826086956) #Exposure of resource to wrong sphere(all:4(0,0,0,0,4);Java:2(0,0,0,0,2);C/C++:1(0,0,0,0,1))
```

##### 基本说明
0. patch p位于方法A中
	* patch p增加了对A的返回值的验证：A可能为source方法  
	- patch p删除了某一方法调用B：B以A的参数作为自身参数且B有发送数据/写入数据的含义，则B可能为sink

1. 补丁说明
* 一般按照以下顺序介绍
	* 针对或者修复的问题是什么（漏洞产生的原因，造成的后果）
	* 修复该漏洞的思路（各个步骤涉及的函数方法）
	* 测试方式：Test
2. diff内容
* 很多情况下修复操作不涉及sanitizer函数，**而是通过添加逻辑来修复，比如权限检查、条件检查等。**
* 一条安全公告可能涉及多个patch链接，一个patch链接可能涉及多个文件的修改，一个文件可能涉及多块修改，每块修改可能涉及多个函数。
* patch新增的代码往往是实现修复功能，可能是sanitizer，但未必涉及敏感信息的无害化处理，也经常不是函数的形式。
* 新增sanitizer函数的调用者很有可能是source或者sink。 

3. 思路
* 拼接（针对单条链接）：补丁说明+多个文件的补丁所在的函数+补丁内容（+，-）
* 提取补丁说明的信息并json格式输出：针对或者修复的问题是什么（漏洞产生的原因，造成的后果）；修复该漏洞的所有步骤（各个步骤涉及的函数方法：在raw_code中查找到这些方法的节点）；测试Test。
``` Java
PatchInformationPrompt_string = """  
You are a vulnerability patch analysis expert. Please read the following patch commit information, \  
which includes the commit message, several sets of patch code and their corresponding original raw code.\  
In the patch code, the lines starting with '+' are added and the lines starting with '-' are removed.\  
Your main task is to extract information regarding the vulnerability patch based on the commit message and the code. \  
The relevant information includes the causes of the vulnerability, the consequences of the vulnerability, the approach taken to fix it, and the test methodology.\  
  
Commit Information:{commit_information}
Answer the following information:{format_instructions}  
"""  

causes_schema = ResponseSchema(name="causes",  
                             description="Extract the cause of the vulnerability.")  
consequences_schema = ResponseSchema(name="consequences",  
                             description="Extract the consequences of the vulnerability.")  
approaches_schema = ResponseSchema(name="approaches",  
                             description="Extract the approach steps taken to fix the vulnerability and the signatures of the functions used for repairment of each approach step.The output's json format is like:{\"step1\":{\"description\":"",\"methods\":[]},\"step2\":{\"description\":"",\"methods\":[]} }")  
test_schema = ResponseSchema(name="test",  
                             description="Extract test methodology.")  
  
```

* 提取sanitizer和source/sink（SimpleSequentialChain）
	* sanitizer：若存在sanitizer s1,则在commit的raw_code文件和补丁相关节点中，查找s1的所有调用者的节点；若不存在sanitizer，则进入下一步。
	* source/sink：从补丁所涉及的函数（被修改的函数，调用的函数）中提取
``` Java
You are a vulnerability patch analysis expert.
1.Please read the following patch commit information, which includes the commit message, several sets of patch code and their corresponding original raw code.
2.In the patch code, the lines starting with '+' are added and the lines starting with '-' are removed.
3.From the perspective of taint analysis, analyze step by step and find out all suspicious source methods, sink methods and sanitizers from patch commit information.
4.The newly added functions in the patch are highly likely to be sanitizers.Sanitizer is not necessarily a function, but can also be a logical modification.

Commit Information:{commit_information}
Answer the following information:{format_instructions}

```

*  分析s1的调用者节点列表：在raw_code中查找到所有调用者方法的节点；结合s1，分析所有调用者是否为潜在source或者sink。
* 格式化返回结果(函数名和对应节点)
	


##### 各CWE类型

* [[Android相关的CWEs/CWE_CVE补丁提取Srm/CWE-200(Information exposure)|CWE-200(Information exposure)]]
* [[Android相关的CWEs/CWE_CVE补丁提取Srm/CWE-862(Missing authorization)|CWE-862(Missing authorization)]]
* [[Android相关的CWEs/CWE_CVE补丁提取Srm/CWE-284(Improper access control)|CWE-284(Improper access control)]]
* [[Android相关的CWEs/CWE_CVE补丁提取Srm/CWE-20(Improper input validation)|CWE-20(Improper input validation)]]


* [[Android相关的CWEs/CWE_CVE补丁提取Srm/CWE-264(Permissions, privileges, and access control)|CWE-264(Permissions, privileges, and access control)]]
* [[Android相关的CWEs/CWE_CVE补丁提取Srm/CWE-287(Improper authentic)|CWE-287(Improper authentic)]]








