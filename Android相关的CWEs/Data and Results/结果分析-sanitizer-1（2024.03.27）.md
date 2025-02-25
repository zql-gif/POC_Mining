### 基本数量
1. P：含有sanitizer的补丁数量（P=TN+FN）
* TP：含有sanitizer并且sanitizer被正确预测出来
* FN：含有sanitizer但是sanitizer没有被正确预测出来
2. N：不含sanitizer的补丁数量（N=FP+TN）
* FP：不含sanitizer但是预测出不正确的sanitizer
* TN：不含有sanitizer并且的确没有给出sanitizer

2. 准确率accuracy
* 反映分类器或者模型对整体样本判断正确的能力，即能将阳性（正）样本positive判定为positive和阴性（负）样本negative判定为negative的正确分类能力。值越大，性能performance越好
* ACC=(TP+TN)/(TP+TN+FP+FN)

3. 精确率precision
* 反映分类器或者模型正确预测正样本精度的能力，即预测的正样本中有多少是真实的正样本。值越大，性能performance越好
* precision=TP/(TP+FP)

4. 召回率recall，也称为真阳率、命中率（hit rate）
* 反映分类器或者模型正确预测正样本全度的能力，增加将正样本预测为正样本，即正样本被预测为正样本占总的正样本的比例。值越大，性能performance越好
* recall=TPR=TP/(TP+FN)=TP/P

5. 误报率false alarm，也称为假阳率、虚警率、误检率
* 反映分类器或者模型正确预测正样本纯度的能力，减少将负样本预测为正样本，即负样本被预测为正样本占总的负样本的比例。值越小，性能performance越好
* false alarm=FPR=FP/(FP+TN)=FP/N

6. 漏报率miss rate，也称为漏警率、漏检率
* 反映分类器或者模型正确预测负样本纯度的能力，减少将正样本预测为负样本，即正样本被预测为负样本占总的正样本的比例。值越小，性能performance越好
* miss rate=FNR=FN/(TP+FN)=FN/P

7. 特异度specificity
* 反映分类器或者模型正确预测负样本全度的能力，增加将负样本预测为负样本，即负样本被预测为负样本占总的负样本的比例。值越大，性能performance越好
* specificity=TNR=TN/(FP+TN)=TN/N

### 分析结果
#### CWE-200（除example外共20个）
1. P（P=TN+FN）：16
* TP（含有sanitizer并且sanitizer被正确预测出来）：15
* FN（含有sanitizer但是sanitizer没有被正确预测出来）：1
2. N（N=FP+TN）：4
* FP（不含sanitizer但是预测出不正确的sanitizer）：1
* TN（不含有sanitizer并且的确没有给出sanitizer）：3

2. 准确率accuracy
* ACC=(TP+TN)/(TP+TN+FP+FN)=(15+3)/(15+3+1+1)=18/20=90.00%

3. 精确率precision
* precision=TP/(TP+FP)=15/(15+1)=15/16=93.75%

4. 召回率recall，也称为真阳率、命中率（hit rate）
* recall=TPR=TP/(TP+FN)=TP/P=15/(15+1)/15/16=93.75%

5. 误报率false alarm，也称为假阳率、虚警率、误检率
* false alarm=FPR=FP/(FP+TN)=FP/N=1/4=25.00%

6. 漏报率miss rate，也称为漏警率、漏检率
* miss rate=FNR=FN/(TP+FN)=FN/P=1/16=6.25%

7. 特异度specificity
* specificity=TNR=TN/(FP+TN)=TN/N=3/4=75.00%


#### CWE-862（除example外共20个）
1. P（P=TN+FN）：17
* TP（含有sanitizer并且sanitizer被正确预测出来）：16
* FN（含有sanitizer但是sanitizer没有被正确预测出来）：1
2. N（N=FP+TN）：3
* FP（不含sanitizer但是预测出不正确的sanitizer）：0
* TN（不含有sanitizer并且的确没有给出sanitizer）：3

2. 准确率accuracy
* ACC=(TP+TN)/(TP+TN+FP+FN)=(16+3)/(16+3+0+1)=19/20=95%

3. 精确率precision
* precision=TP/(TP+FP)=16/(16+0)=100%

4. 召回率recall，也称为真阳率、命中率（hit rate）
* recall=TPR=TP/(TP+FN)=TP/P=16/17=94.12%

5. 误报率false alarm，也称为假阳率、虚警率、误检率
* false alarm=FPR=FP/(FP+TN)=FP/N=0

6. 漏报率miss rate，也称为漏警率、漏检率
* miss rate=FNR=FN/(TP+FN)=FN/P=1/17=5.88%

7. 特异度specificity
* specificity=TNR=TN/(FP+TN)=TN/N=

8. index=48检测出一个合理但是我没有标注的sanitizer
#### CWE-284（除example外共14个）
1. P（P=TN+FN）：11
* TP（含有sanitizer并且sanitizer被正确预测出来）：11
* FN（含有sanitizer但是sanitizer没有被正确预测出来）：0
2. N（N=FP+TN）：3
* FP（不含sanitizer但是预测出不正确的sanitizer）：1
* TN（不含有sanitizer并且的确没有给出sanitizer）：2

2. 准确率accuracy
* ACC=(TP+TN)/(TP+TN+FP+FN)=(11+2)/(11+2+1+0)=13/14=92.86%

3. 精确率precision
* precision=TP/(TP+FP)=11/(11+1)=11/12=91.67%

4. 召回率recall，也称为真阳率、命中率（hit rate）
* recall=TPR=TP/(TP+FN)=TP/P=11/11=100.00%

5. 误报率false alarm，也称为假阳率、虚警率、误检率
* false alarm=FPR=FP/(FP+TN)=FP/N=1/3=33.33%

6. 漏报率miss rate，也称为漏警率、漏检率
* miss rate=FNR=FN/(TP+FN)=FN/P=0

7. 特异度specificity
* specificity=TNR=TN/(FP+TN)=TN/N=2/3=66.67%

8. index=30检测出一个合理但是我没有标注的sanitizer
#### CWE-20（除example外共13个）
1. P（P=TN+FN）：9
* TP（含有sanitizer并且sanitizer被正确预测出来）：8
* FN（含有sanitizer但是sanitizer没有被正确预测出来）：1
2. N（N=FP+TN）：4
* FP（不含sanitizer但是预测出不正确的sanitizer）：0
* TN（不含有sanitizer并且的确没有给出sanitizer）：4

2. 准确率accuracy
* ACC=(TP+TN)/(TP+TN+FP+FN)=(8+4)/(8+4+0+1)=12/13=92.31%

3. 精确率precision
* precision=TP/(TP+FP)=8/(8+0)=100%

4. 召回率recall，也称为真阳率、命中率（hit rate）
* recall=TPR=TP/(TP+FN)=TP/P=8/9=88.89%

5. 误报率false alarm，也称为假阳率、虚警率、误检率
* false alarm=FPR=FP/(FP+TN)=FP/N=0

6. 漏报率miss rate，也称为漏警率、漏检率
* miss rate=FNR=FN/(TP+FN)=FN/P=1/9=11.11%

7. 特异度specificity
* specificity=TNR=TN/(FP+TN)=TN/N=4/4=100%


#### 合计（除example外共67个）
1. P（P=TN+FN）：16+17+11+9=53
* TP（含有sanitizer并且sanitizer被正确预测出来）：15+16+11+8=50
* FN（含有sanitizer但是sanitizer没有被正确预测出来）：1+1+0+1=3(CWE-200:14;CWE-862:46;CWE-20:34)
2. N（N=FP+TN）：4+3+3+4=14
* FP（不含sanitizer但是预测出不正确的sanitizer）：1+0+1+0=2(CWE-200:46;CWE-284:20)
* TN（不含有sanitizer并且的确没有给出sanitizer）：3+3+2+4=12

2. 准确率accuracy
* ACC=(TP+TN)/(TP+TN+FP+FN)=(50+12)/(50+12+2+3)=62/67=92.54%

3. 精确率precision
* precision=TP/(TP+FP)=50/(50+2)=50/52=96.15%

4. 召回率recall，也称为真阳率、命中率（hit rate）
* recall=TPR=TP/(TP+FN)=TP/P=50/53=94.34%

5. 误报率false alarm，也称为假阳率、虚警率、误检率
* false alarm=FPR=FP/(FP+TN)=FP/N=2/14=14.29%

6. 漏报率miss rate，也称为漏警率、漏检率
* miss rate=FNR=FN/(TP+FN)=FN/P=3/53=5.66%

7. 特异度specificity
* specificity=TNR=TN/(FP+TN)=TN/N=12/14=85.71%
