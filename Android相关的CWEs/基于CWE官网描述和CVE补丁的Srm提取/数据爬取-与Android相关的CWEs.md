## 1.论文结论（论文1704.03356）

![Snipaste_2024-01-30_12-04-31](https://nicklorry.oss-cn-beijing.aliyuncs.com/typora-image/Android-related-CWEs.jpg)


```
# CWE-438 Behavioral problem
## CWE-840 Business logic errors
### CWE-696 Incorrect behavior order
### CWE-799 Improper control of interaction frequency

# CWE-703 Improper check or handling of exceptional conditions
## CWE-252 Unchecked return value
## CWE-129 Improper validation of array index
## CWE-746 Error handling
### CWE-391 Unchecked error condition
## CWE-248 Uncaught Exception

# CWE-19 Data handling
## CWE-118 Improper access of indexable resource
## CWE-189 Numeric errors
### CWE-195 Signed to unsigned conversion error
### CWE-192 Integer coercion error
### CWE-682 Incorrect calculation
#### CWE-190 Integer overflow
#### CWE-191 Integer underflow
#### CWE-193 Off-by-one error
## CWE-136 Type errors
## CWE-133 String errors
### CWE-134 Use of externally-controlled format string
## CWE-228 Improper handling of syntactically invalid structure
### CWE-233 Improper handling of parameters
#### CWE-234 Failure to handle missing parameter
## CWE-140 Improper neutralization of delimiters
### CWE-144 Improper neutralization of line delimiters
## CWE-199 Information management errors
### CWE-200 Information exposure
#### CWE-201 Information exposure through sent data
#### CWE-209 Information exposure through an error message
##### CWE-210 Exposure through self-generated error message
#### CWE-215 Information exposure through debug information

# CWE-227 Improper fulfillment of API contract
## CWE-648 Incorrect use of privileged API

# CWE-632 Weaknesses that affect files or directories
## CWE-434 Unrestricted upload of files with dangerous type
## CWE-22 Improper limitation of pathname to restricted d directory
### CWE-23 Relative path traversal

# CWE-254 Security features
## CWE-310 Cryptograp. issues(Cryptographic Issues)
### CWE-311 Missing encryption of sensitive data
#### CWE-319 Cleartext transmission of sensitive information
### CWE-326 Inadequate encryption strength
### CWE-320 Key management errors
### CWE-325 Missing required cryptographic step
### CWE-327 Use of a broken or risky cryptographic algorithm
## CWE-355 User interface security issues
## CWE-255 Credentials management
## CWE-285 Improper authorizat.
### CWE-732 Incorrect permission assignment for critical resource
### CWE-862 Missing authorization
## CWE-295 Improper certificate validation
### CWE-296 Improper following of certificate's chain of trust
## CWE-330 Use of insufficiently random values
### CWE-340 Predictability problems
## CWE-287 Improper authentic.(Improper Authentication)
### CWE-304 Missing critical step in authentication
### CWE-384 Session fixation
## CWE-345 Insufficient verification of data authenticity
### CWE-79 Cross-site scripting
### CWE-347 Improper verification of cryptographic signature

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

# CWE-713 Injection flaws
## CWE-94 Code injection
## CWE-89 SQL injection
## CWE-77 Command injection

# CWE-361 Time and state
## CWE-1061 Insufficient encapsulation
### CWE-749 Exposed dangerous method or function
## CWE-668 Exposure of resource to wrong sphere
### CWE-375 Returning a mutable object to untrusted caller
## CWE-691 Insufficient control flow management
### CWE-834 Excessive iteration
#### CWE-835 Loop with unreachable exit condition
### CWE-362 Race condition
#### CWE-366 Race condition within a thread

# CWE-465 Pointer issues
## CWE-825 Expired pointer dereference
### CWE-416 Use after free
## CWE-824 Access of uninitialized pointer
## CWE-587 Assignment of a fixed address to a pointer
## CWE-476 NULL pointer dereference
## CWE-763 Release of invalid pointer or reference
## CWE-822 Untrusted pointer dereference
## CWE-823 Use of out-of-range pointer offset

# CWE-452 Initialization and cleanup errors
## CWE-455 Non-exit on Failed Initialization
## CWE-665 Improper initialization
### CWE-457 Use of uninitialized variable
### CWE-909 Missing initialization of resource
### CWE-456 Missing initialization of variable
## CWE-459 Incomplete cleanup
### CWE-226 Sensitive information uncleared before release

# CWE-20 Improper input validation
## CWE-99 Improper control of resource identifiers
### CWE-694 Use of multiple resources with duplicate identifier
## CWE-622 Improper validation of function arguments
## CWE-170 Improper null termination
## CWE-680 Integer overflow to buffer overflow
## CWE-100 Technology- specific input validation problems
## CWE-606 Unchecked input for loop condition

# CWE-398 Indicator of poor quality code
## CWE-399 Resource management errors
### CWE-669 Incorrect resource transfer between spheres
#### CWE-434 Unrestricted upload of file with dangerous type
### CWE-415 Double free
### CWE-400 Uncontrolled resource consumption
#### CWE-770 Allocation of resources without limits or throttling
##### CWE-789 Uncontrolled memory allocation
#### CWE-779 Logging of excessive data
### CWE-404 Improper resource shutdown or release
### CWE-411 Resource locking problems
### CWE-502 Deserializat. of untrusted data(Deserialization of Untrusted Data)
## CWE-676 Use of potentially dangerous function

# CWE-633 Weaknesses that affect memory
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

>  Total 139 CWEs

## 2.爬取选定的CWE类别对应的CVEs补丁信息 （2015-2025）
### 重要链接
* [Google Android : CVE security vulnerabilities, versions and detailed reports (cvedetails.com)](https://www.cvedetails.com/product/19997/Google-Android.html?vendor_id=1224)
* [Android 安全公告和更新公告  |  Android 开源项目  |  Android Open Source Project](https://source.android.com/docs/security/bulletin?hl=zh-cn)
* [CWE - Common Weakness Enumeration (mitre.org)](https://cwe.mitre.org/index.html)
* [Google Android : CVE security vulnerabilities, versions and detailed reports (cvedetails.com)](https://www.cvedetails.com/product/19997/Google-Android.html?vendor_id=1224)提供了与android有关的各类CWE的CVE数量和详细情况（包括commit信息，[Android 安全公告和更新公告  |  Android 开源项目  |  Android Open Source Project](https://source.android.com/docs/security/bulletin?hl=zh-cn)）。
* （[Downloads | CVE](https://www.cve.org/Downloads)对应的压缩包内的commit信息就是来自于[Android 安全公告和更新公告  |  Android 开源项目  |  Android Open Source Project](https://source.android.com/docs/security/bulletin?hl=zh-cn)）的，因此没有考虑从这个网站的压缩包中获取数据。
### 爬取过程（更新至最新到2025年的）
1. Crawler_AndroidSecurityBulletin.py（结果存储在'SecurityBulletinResults/' + Year + '/'+YM+ '.jsonl'）
	* 爬取Android安全公告和更新公告的数据（2015-2024年），爬取2015-2024年每个月的Android安全公告信息，爬取如下全部表格中的（CVE-ID，urls）
	* ![[Pasted image 20240201213815.png]]
	* 结果：数据格式（**未合并2010条，合并后1997条**）
2.  CWE_CVEs_Process.py：为上一步获取到android报告的的cves，获取其对应的cwe列表，最后进行合并，得到最终的(CWE, CVE-IDs)，结果在CWE_CVEs文件夹Android_CWE-CVEs.jsonl中
3. Crawler_Patches.py：
	* FilterCWETypes(type)：读取**选中的CWE类别**对应的所有CVE-IDs（BO的10个+DF的1个=>BO的5个+DF的1个）
		* 总数：(CWE 6 , CVE 467)
		* BO分类：CWE-119(137),CWE-120(16),CWE-122(4),CWE-131(3),CWE-787(290)
		* DF分类：CWE-415(17)
	* Merge_CVE_urls(type)：遍历函数 FilterCWETypes(type)读取到的CVE-IDs信息，在第1步中爬取的（CVE-ID，urls）数据中查询对应的参考链接，得到新的（CWE-selected,CVE-ID-selected,url-selected）数据集合，结果文件存储在文件夹CWE_CVE_ID_Urls_selected中
	```
	   结果数目：
		* BufferOverflow总有效CWE_CVEID_urls数量：450
		* BufferOverflow总无效CWE_CVEID_urls数量：450
	    
		* DoubleFree总有效CWE_CVEID_urls数量：17
		* DoubleFree总无效CWE_CVEID_urls数量：17
    ```
	* CrawlCommit(type)：遍历所有的（CWE-selected,CVE-ID-selected,url-selected）数据集合，访问url-selected链接，链接的页面如下图。点击diff后读取需要的数据(读取存储为下面的格式)，结果存储在文件夹FinalCommitResults内。
	    ![[Pasted image 20240201220634.png]]
	    
		``` 
	    结果格式：
	    merge_data['index'] = index  
	    merge_data['cve_id'] = cve_id  
	    merge_data['CWE'] = CWE  
	    merge_data['origin_message'] = message 
	    merge_data['html_url'] = html_url 
	    merge_data['details'] = [  
	      ['raw_url','language','raw_code','patch'],     
	       …………
	       ]
	    ```

		``` 
	    结果数目：
	    BufferOverflow总有效CWE_CVEID_urls数量:450
	    BufferOverflow最终爬取数量：450
	    
	    DoubleFree总有效CWE_CVEID_urls数量:17
	    DoubleFree最终爬取数量：17


        C/C++相关的数目：
	    BufferOverflow最终爬取数量：382
	    BufferOverflow分类(C相关/总数)：CWE-119(117/137),CWE-120(10/16),CWE-122(4/4),CWE-131(1/3),CWE-787(250/290)
	    
	    DoubleFree最终爬取数量：15
		DoubleFree分类：CWE-415(15/17)
	    ```

4. LoadDataFunc.py查询读取结果数据
``` Python
#从FinalCommitResults中读取特定type的特定CWEType的特定cve_id的数据,并写到对应json文件(res_filename)中
LoadTypeCWE('LoadDataResults/temp.txt', type="PrivilegeEscalation", CWEType="CWE-20", cve_id="CVE-2017-0475")
```


