### CWE选型
* [CWE - Common Weakness Enumeration (mitre.org)](https://cwe.mitre.org/index.html)
* SWAN：CWE-78、CWE-79、CWE-W89、CWE-306、CWE-601、CWE-862和CWE-863
* Android报告的CWE数量
```
('CWE-125', 0.17771739130434783)  #Out-of-bounds read(selected)
('CWE-787', 0.10163043478260869)  #Out-of-bounds write(selected)
('CWE-200', 0.10135869565217391)  #Information exposure(selected)
('CWE-862', 0.09320652173913044)  #Missing authorization(selected)
('CWE-119', 0.0654891304347826)   #Improper restriction of operations in the bounds of memory buffer(unknown)
('CWE-284', 0.057608695652173914) #Improper access control(selected)
('CWE-20', 0.05597826086956522)   #Improper input validation(selected)
0.6529891304347827

('CWE-264', 0.03885869565217391)  #Permissions, privileges, and access control(selected:包含CWE-284)
('CWE-190', 0.03152173913043478)  #Integer Overflow or Wraparound(pass)
0.7233695652173914

('CWE-203', 0.02391304347826087) #Observable Discrepancy(selected)
('CWE-287', 0.02309782608695652) #Improper authentic(selected)
0.7703804347826088


('CWE-416', 0.018206521739130434) #Use after free_Pointer issues(pass)
('CWE-908', 0.01548913043478261)  #Use of Uninitialized Resource(selected)
('CWE-285', 0.012771739130434783) #Improper authorizat(selected)
('CWE-120', 0.011684782608695652) #Buffer copy without checking size of input(pass)
0.8285326086956523

('CWE-276', 0.010869565217391304) #Incorrect default permissions(selected)
('CWE-668', 0.010054347826086956) #Exposure of resource to wrong sphere(selected)
0.8494565217391306
```

### Prompt
#### 中文
``` Prompt
requirement_string = """
你是污点分析专家。请阅读附上的示范示例，该示例由三个反引号分隔，并根据污染分析和CWE的概念提取任何可疑的source，sink或sanitizer方法。＼
可能有，也可能没有。一步一步地分析它们，并给出你分析的理由
这里有一些关于source、sink和sanitizer的基本概念:{concepts}\
example:'''{example}'''
回答以下信息:{format_instructions}
"""

concepts_string = """
source方法:定义为读取共享资源并将非常量值返回到应用程序代码中的方法。
sink方法:定义为将非常量值写入应用程序上下文之外的共享资源的方法。
共享资源:Android中共享资源的例子包括文件系统、网络连接和系统广播。
snaitizer方法:这种方法通常通过数据加密等技术确保数据传播不再对软件系统构成安全威胁。
"""

example_string = """
"""
```

#### 英文
``` Prompt
  
requirement_string = """  
You are a tainted analysis expert. Please read the demonstrative example enclosed that is delimited by triple backticks and extract any suspicious source, sink, or sanitizer  method based on the concepts of tainted analysis and CWE. \  
It's possible that there may or may not be any.Analyze them step by step and provide reasons for your analysis.\  
Here are some basic concepts regarding sources, sinks, and sanitizers:{concepts} \  
example:```{example}```  
Answer the following information:{format_instructions}  
"""  
# 编写一个提示模板  
prompt_template = ChatPromptTemplate.from_template(requirement_string)  
  
concepts_string = """  
Source method:defined as methods that read shared resources and return non-constant values into the application code.\  
Sink method: defined as methods that write a non-constant value to a shared resource outside the application context. \  
Shared resource:examples of shared resources in Android include the file system, network connections,and system broadcasts.\  
Sanitizer method: this method generally ensures that data propagation no longer poses a security threat to the software system, often through techniques like data encryption.  
"""  
   
  
source_schema = ResponseSchema(name="source",  
                             description="Extract suspicious source method name,and output explanations of reasons.The json format is like:{\"name\":'',\"reason\":''}.")  
sink_schema = ResponseSchema(name="sink",  
                             description="Extract suspicious sink method name,and output explanations of reasons as a comma separated Python list.The json format is like:{\"name\":'',\"reason\":''}.")  
sanitizer_schema = ResponseSchema(name="sanitizer",  
                             description="Extract suspicious sanitizer method name,and output explanations of reasons as a comma separated Python list.The json format is like:{\"name\":'',\"reason\":''}.")  
  
response_schemas = [source_schema,  
                    sink_schema,  
                    sanitizer_schema]  
  
output_parser = StructuredOutputParser.from_response_schemas(response_schemas)  
format_instructions = output_parser.get_format_instructions()  
```


### CWE-125(Out-of-bounds read)
```
#### CWE-125 Out-of-bounds read
##### CWE-126 Buffer over-read
```
### CWE-787(Out-of-bounds write)
```
### CWE-787 Out-of-bounds write
#### CWE-121 Stack-based buffer overflow
#### CWE-124 Buffer underwrite
#### CWE-122 Heap-based buffer overflow
#### CWE-823 Use of out-of-range pointer offset
```
### [[Android相关的CWEs/CWE官网描述（英文）/CWE-200(Information exposure)]]

```
### CWE-200 Information exposure
#### CWE-201 Information exposure through sent data
#### CWE-209 Information exposure through an error message
##### CWE-210 Exposure through self-generated error message
#### CWE-215 Information exposure through debug information
```

结果：[[CWE-200]]
### [[Android相关的CWEs/CWE官网描述（英文）/CWE-862(Missing authorization)]]

```
### CWE-862 Missing authorization
```

### CWE-119(Improper restriction of operations in the bounds of memory buffer
```
## CWE-119 Improper restriction of operations in the bounds of memory buffer
### CWE-787 Out-of-bounds write
#### CWE-121 Stack-based buffer overflow
#### CWE-124 Buffer underwrite
#### CWE-122 Heap-based buffer overflow
#### CWE-823 Use of out-of-range pointer offset
### CWE-120 Buffer copy without checking size of input
### CWE-131 Incorrect calculation of buffer size
### CWE-788 Access of memory location after end of buffer
#### CWE-125 Out-of-bounds read
##### CWE-126 Buffer over-read
### CWE-805 Buffer access with incorrect length value
#### CWE-806 Buffer access using size of source buffer
```

### [[Android相关的CWEs/CWE官网描述（英文）/CWE-284(Improper access control)]]

```
## CWE-284 Improper access control
### CWE-923 Improper restriction of comm. channel to intended endpoints
#### CWE-926 Improper export of Android application components
### CWE-282 Improper ownership management
### CWE-269 Improper privilege management
### CWE-782 Exposed IOCTL with insufficient access control

```

结果：[[CWE-284]]
### [[Android相关的CWEs/CWE官网描述（英文）/CWE-20(Improper input validation)]]
```
# CWE-20 Improper input validation
## CWE-99 Improper control of resource identifiers
### CWE-694 Use of multiple resources with duplicate identifier
## CWE-622 Improper validation of function arguments
## CWE-170 Improper null termination
## CWE-680 Integer overflow to buffer overflow
## CWE-100 Technology- specific input validation problems
## CWE-606 Unchecked input for loop condition
```
结果：[[CWE-20]]
### [[Android相关的CWEs/CWE官网描述（英文）/CWE-264(Permissions, privileges, and access control)]]
```
# CWE-264 Permissions, privileges, and access control
## CWE-265 Privilege / sandbox issues
## CWE-275 Permission issues
### CWE-276 Incorrect default permissions
### Cookie forcing
## CWE-284 Improper access control
### CWE-923 Improper restriction of comm. channel to intended endpoints
#### CWE-926 Improper export of Android application components
### CWE-282 Improper ownership management
### CWE-269 Improper privilege management
### CWE-782 Exposed IOCTL with insufficient access control
```
结果：[[Android相关的CWEs/CWE官网Examples提取Srm结果/CWE-264]]
### CWE-190(Integer Overflow or Wraparound)
```
#### CWE-190 Integer overflow
```

### CWE-203(Observable Discrepancy)


### [[Android相关的CWEs/CWE官网描述（英文）/CWE-287(Improper authentic)]]
```
## CWE-287 Improper authentic.(Improper Authentication)
### CWE-304 Missing critical step in authentication
### CWE-384 Session fixation
```


### CWE-416(Use after free_Pointer issues)
```
### CWE-416 Use after free
```


### CWE-908(Use of Uninitialized Resource)

### CWE-285(Improper authorizat
```
## CWE-285 Improper authorizat.
### CWE-732 Incorrect permission assignment for critical resource
### CWE-862 Missing authorization
```

### CWE-120(Buffer copy without checking size of input)
```
### CWE-120 Buffer copy without checking size of input
```

### CWE-276(Incorrect default permissions)
```
### CWE-276 Incorrect default permissions
```

### CWE-668(Exposure of resource to wrong sphere
```
## CWE-668 Exposure of resource to wrong sphere
### CWE-375 Returning a mutable object to untrusted caller
```


### Android相关的CWE
```
438,840,696,799,
703,252,129,746,391,248,
19,118,189,195,192,682,190,191,193,136,133,13,228,233,234,140,144,199,200,201,209,210,215,
227,648,
632,434,22,23,
254,310,311,319,326,320,325,327,355,255,285,732,862,295,296,330,340,287,304,384,345,79 ,347,
264,265,275,276,284,923,926,282,269,782,
713,94,89,77,
361,1061,749,668,375,691,834,83,36,366,
46,825,416,824,587,476,763,822,823,
452,455,665,457,909,456,459,226,
20,99,694,622,170,680,100,606,
398,399,669,434,41,400,77,789,779,404,411,502,676,
63,119,787,121,124,122,823,120,131,788,125,126,80,806
```