## 格式
**论文名**  
-出处  
-关键词  
-研究关注点  
-简单总结:  
--(可选)解决的问题，研究方法  
-文件名  

# 问题揭露类  
## 小程序
### 请求伪造
**Cross Miniapp Request Forgery: Root Causes, Attacks, and Vulnerability Detection**  
ccs 2022  
请求伪造，输入验证，跨小程序  
跨小程序请求伪造漏洞  
总结：论文发现小程序中应用id验证缺失或不安全的数据共享行为会导致跨小程序请求伪造问题。分析的目标是小程序之间。研究方法：静态分析检测是否有id检测等身份验证  
ccs22-CrossMiniappRequestForgery  

**MiniCAT: Understanding and Detecting Cross-Page Request Forgery Vulnerabilities in Mini-Programs**  
ccs2024  
请求伪造，路由伪造，身份验证缺失，跨界面  
小程序内不同界面间的请求伪造漏洞  
总结：发现小程序缺少身份和url安全检验会导致界面间的请求伪造。研究方法：静态分析是否有url合法性验证和身份状态验证  
ccs24-MiniCAT  

### 凭证泄露
**Don't Leak Your Keys: Understanding, Measuring, and Exploiting the AppSecret Leaks in Mini-Programs**  
ccs2023  
AppSecret  
小程序AppSecret泄露  
总结：论文发现大量小程序存在将AppSecret硬编码到前端小程序代码中的现象，该行为会导致攻击者获得访问隐私数据的权限。研究方法：静态分析小程序代码发现漏洞  
ccs23-Don’t Leak Your Keys  

**The Skeleton Keys: A Large Scale Analysis of Credential Leakage in Mini-apps**  
ndss2025  
凭证泄露，前端，服务端  
小程序凭证泄露  
总结：论文发现一些小程序存在将本应保存在服务端的身份凭证硬编码或不安全的传输到前端代码导致凭证泄露。研究方法：总结凭证使用规则，静态检测前端代码中是否不安全的使用凭证  
ndss25-The Skeleton Keys  

### 统计分析
**Understanding Miniapp Malware: Identification, Dissection, and Characterization**  
ndss2025  
小程序数据集，malware  
收集大量小程序，总结恶意行为  
总结：类似综述，论文收集了多年、大量小程序，分析收集过程中被下架的小程序，总结恶意行为特征。  
ndss25-Understanding Miniapp Malware  

**Characterizing and Detecting Bugs in WeChat Mini-Programs**  
icse2022  
小程序收集，bug分析  
分析有漏洞的小程序，总结bug特征  
总结：论文收集了论坛、开源数据集等多方面的存在漏洞的小程序，分析并总结了这些漏洞的形成原因和特征。  
icse22-Characterizing and Detecting Bugs in WeChat Mini-Programs  

## 小程序+平台应用
### 访问控制
**Demystifying Resource Management Risks in Emerging Mobile App-in-App Ecosystems**  
ccs 2020  
访问控制，资源滥用，钓鱼攻击，性能干扰  
平台应用对小程序的权限访问控制  
总结：论文发现了⼀个小程序平台应用的资源管理漏洞，攻击者的小程序可以在不需要权限的情况下获取敏感数据，并存在⽹络钓⻥攻击的潜在⻛险。研究方法：  
ccs20-DemystifyingResourceManagementRisksinEmergingMobileApp-in-AppEcosystems  

**Identity Confusion in WebView-based Mobile App-in-app Ecosystems**  
usenixsecurity2022  
身份模糊，权限，web域名，应用id身份  
平台给小程序提供的权限范围模糊  
总结：研究发现平台给小程序提供的权限控制存在缺陷，存在域名模糊，id模糊，权限控制不精确。研究方法：动态和静态结合静态分析：分析迷你应用的代码和配置文件，识别潜在的身份验证和授权问题。动态分析：通过模拟应用的运行，测试不同身份在WebView中的表现，检测API调用、权限控制和身份验证是否存在问题。  

### API分析
**Uncovering and Exploiting Hidden APIs in Mobile Super Apps**  
ccs2023  
隐藏的API，跨平台，多平台应用  
平台应用开发文档中没有说明的API  
总结：论文检测了微信、支付宝等提供小程序运行环境的平台应用，发现多个应用都存在隐藏的API，并且部分API存在安全风险，比如没有进行权限检测。研究方法：静态分析寻找隐藏的api，动态分析影响  
ccs23-Uncovering and Exploiting Hidden APIs in Mobile Super Apps  

**One Size Does Not Fit All: Uncovering and Exploiting Cross Platform Discrepant APIs in WeChat**  
usenixsecurity2023  
api，跨平台差异  
api跨平台差异  
总结：研究发现微信平台给小程序提供的API在不同平台上出现差异，一些差异会导致安全问题。研究方法：不同平台上测试api检查执行结果  
usenixsecurity23-One Size Does Not Fit All  

# 代码分析类：
## 静态分析
**ELDetector: An Automated Approach Detecting Endless-loop in Mini Programs**  
icse2025  
检查代码中无限循环问题  
论文暂无  

**TAINTMINI: Detecting Flow of Sensitive Data in Mini-Programs with Static Taint Analysis**  
icse2023  
静态污点分析  
总结：开发了小程序静态污点分析框架，提出通用控制流图  
icse23TaintMini  

**WeMinT: Tainting Sensitive Data Leaks in WeChat Mini-Programs**  
ase2023  
静态污点分析  
总结：开发了小程序静态污点分析框架  
ase23-WeMinT  

**MiniChecker: Detecting Data Privacy Risk of Abusive Permission Request Behavior in Mini-Programs**  
ase2024  
权限申请，静态分析  
检测不正当的权限申请  
静态分析构建函数调用图，识别恶意行为（循环弹窗，重复弹窗等）  
ase24-MiniChecker  


## 动态分析
**A Unified Framework for Mini-game Testing: Experience on WeChat**  
fse2023  
小游戏，GUI测试  
小游戏GUI测试  
总结：动态测试小程序图形界面  
fse23-A Unified Framework for Mini-game Testing  

**Industry practice of JavaScript Dynamic Analysis on WeChat Mini-Programs**  
ase2020  
js，动态分析  
js动态分析小程序版  
ase20-Industry practice of JavaScript Dynamic Analysis on WeChat Mini-Programs  

## 动静结合

**JSidentify: A Hybrid Framework for Detecting Plagiarism Among JavaScript Code in Online Mini Games**  
icse2020  
代码抄袭，混淆  
检测小程序中的代码抄袭  
总结：论文提出一种静态分析结合动态分析的检测小程序中的代码抄袭的方法。  
icse20-JSidentify  
