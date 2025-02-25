## 总体设计
### 总体思路
1. 结合补丁说明和补丁提取sanitizer：补丁中的sanitizer修复以Security Check类型的为主，少量Data transformation类型的
2. 从sanitizer的位置进行前向或后向分析，确定敏感数据后确定可疑的source，sink  
---
### 补丁中的sanitizer

#### 补丁中的sanitizer定义
1. 特点
* sanitizer一般在新增内容中，sanitizer的形式主要是Security Check类型的，少量Data transformation类型的。
* Data transformation：该类型sanitizer，敏感数据在参数列表中。根据敏感数据在上下文寻找source/sink。
* Security Check（**先权限检查或限制权限，再读取敏感数据**）：读取或泄露敏感数据的代码一般在sanitizer的后面，sanitizer往往截断或者避免后续导致敏感数据泄露的操作。因此，我认为可疑的source/sink位于sanitizer代码之后（据我观察主要是source，比如：if条件判断中添加了权限检查，不满足权限则进入if分支内的Security handling statement进行处理；满足权限则向后执行代码）。

2. sanitizer的定义（结合VulChecker一文中的定义和补丁的特点）：VulChecker一文中提到现有方法识别sanitizer常忽略自定义函数和安全检查语句这两种类型。
* sanitizers大致分两类：Data transformation和Security Check（分类依据：指令是否直接修改数据，前者直接修改数据，后者往往不直接修改）
* Data transformation:
	* Substitution：使用substitution操作来替换数据中的敏感字符。(例如在防止目录遍历时可以用空字符替换字符串“../”字符串。)
	* Splicing：为了确保数据的安全性和可控性，开发人员通常会在数据的前端或末尾拼接其他数据。(例如，为了防止文件包含漏洞，可以在原始文件名之前拼接路径或拼接类型名称。）
	* Escape：一些字符可以截断语句、关闭前向数据，甚至执行命令。开发人员经常对字符串使用转义操作。它移除字符的特殊含义，并将其转义到无害的字符中。
	* Decoding：通过编码将字符转换成更安全的格式。
* Security Check：开发人员定义专门用于强制安全检查的函数，函数内包括安全检查逻辑代码；或者在已有函数内添加安全检查逻辑代码。**安全检查逻辑一般分以下两个层次：**
	* Check statement：主要由**条件分支语句**组成，对数据特性（一般为权限检查）进行分析，选择要执行的后续分支；还有try-catch语句也是较为典型的，try中进行检查,catch捕捉异常返回代码。
	* Security handling statement：通过分析数据，程序选择一个不同的分支执行。如果它是正常的，程序将继续执行。如果判断有异常存在，则执行安全处理语句。（Data transformation，exception handling functions or statements，exception return codes）

#### 数据集标注（主要针对sanitizer）
共标注了71个补丁，标注对应的sanitizer并简要说明理由，标注部分较为明显的source/sink。
```
各类型标注数/总数
CWE-200:22/44;
CWE-862:21/49;
CWE-284:15/18;
CWE-20:13/39;
```

* [[Android相关的CWEs/CWE_CVE补丁提取Srm/CWE-200(Information exposure)|CWE-200(Information exposure)]]
* [[Android相关的CWEs/CWE_CVE补丁提取Srm/CWE-862(Missing authorization)|CWE-862(Missing authorization)]]
* [[Android相关的CWEs/CWE_CVE补丁提取Srm/CWE-284(Improper access control)|CWE-284(Improper access control)]]
* [[Android相关的CWEs/CWE_CVE补丁提取Srm/CWE-20(Improper input validation)|CWE-20(Improper input validation)]]


---
### 提取补丁中的sanitizer

#### 提取思路和过程
1. 拼接补丁代码：拼接一条记录中所又被修改文件的所有补丁块（注：提取sanitizer暂不添加完整的原代码；对于Test.java文件，暂不加入到prompt中。降低分析代价）。
2. prompt：分析要求+sanitizer定义说明+few-shot（包含分析流程作为思维链提示）
``` Java
# 提取sanitizer  
SrmPrompt1_string = """  
Let's think step by step.\  1.Patch commit information includes the commit message and several sets of patch code.\  2.In patch code, the lines starting with '+' are added,the lines starting with '-' are removed.\  3.According to the definition of sanitizers(which can be functions or codes block),find out all suspicious sanitizers from patch commit information.\  
Definition of sanitizers:{sanitizer_definition}  
Patch Commit Information:{commit_information}  
Examples:{examples}
Answer the following information:{format_instructions}  
"""  
  
sanitizer_definition = """  
Sanitizers has two categories:\  
1. Data Transformation: Functions that validates,transforms or conditionally modifies sensitive data into safe format with the following possible methods,and so on.  
1.1 Substitution: Substituting sensitive characters with other characters.\  
1.2 Splicing: Concatenate additional data at the beginning or end of the data.\  
1.3 Escape: Use escape operations on strings to remove the special meaning of characters which may cause command execution.\  
1.4 Decoding: Converting characters into a more secure format through encoding.\  
1.5 Others\  
  
2. Security Check: there are two typical types.\  
2.1 Security Check Function:functions specifically for enforcing security checks. These functions contain the logic for performing security checks.\  
2.2 Security Check Logic:Its codes often contain two levels:\  
- Check statement: This often be conditional branch statements(such as if,switch or try-catch) that analyze data characteristics (e.g., permission checks,input restrictions,id checks and so on). It can also be try-catch statement where the check is performed within the try block and any exceptions are caught.\  
- Security handling: In the branch that fails to satisfy the check,the security handling is executed to fix the vulnerability, which involves data transformation, exception handling functions or statements, and returning exception codes.\  
"""
```
3. 格式化输出：
``` Java
版本1：check statement和security handling的识别结果切分不够精准，放弃细分。
{  
    "Data Transformation": {  
      "function signature": "None"  
    },  
    "Security Check Function": {  
      "function signature": "None"  
    },  
    "Security Check Logic": {  
      "check statement":"if, (msg != null)",  
      "security handling":"Log.w(TAG, \"Ignoring content changes for \" + uri + \" from \" + uid + \": \" + msg);\n           return;"    }  
      "index": 0,  
}  

版本2：Security Check Logic提取整体代码，后续再进行分层。添加line range指示改代码的行数信息
{  
    "Data Transformation": {  
        "function signature": "None",  
        "line range": "None"  
    },  
    "Security Check Function": {  
        "function signature": "enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, \"Need BLUETOOTH PRIVILEGED permission\")",  
        "line range": "@@ -2314,6 +2314,8 @@"  
    },  
    "Security Check Logic": {  
        "code block": "None",  
        "line range": "None"  
    },  
    "index": 44  
},
```
4. few-shot：
* 未提供样例时，即使规定了输出格式，输出的答案也不符合要求（不存在对应类型的未按照要求输出为None；未按照要求输出函数签名；Security Check Logic代码范围有偏差）
*  为要提取的三种sanitizer类型找工四种典型样例作为提示：输出的结果格式更正确，定位也较为准确。一开始样例过长效果较差，简化样例后分析效果更好（共简化两次，第一次简化后效果变好，第二次简化后token代价略下降）。
* [[Few shot-simplified]]  [[few-shot]] 

#### 提取结果
[[结果分析-sanitizer-1（2024.03.27）#合计（除example外共67个）]]

---

## 其他
1. 对于多组commit共同构成一组修复的情况，需要合并起来分析
2. 后续需要添加爬取修改后的patch文件代码，因为添加的函数的完整代码位于修改后文件中
3. 后续需要修改爬取思路，将爬取行为和llm分析串联起来
4. GPTScan的论文，仿照它的prompt
5. 如果上面的效果不好，三种分开进行检测？？形成一个带记忆的窗口（效果不好）
6. 加一个分析多次然后做出决策??(较长的prompt，超过多少token就用一下4)
7. 加漏报的解决方法：将误报信息返给llm（可能当成规则反馈给llm）

