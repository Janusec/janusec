# [Janusec Application Gateway / JANUSEC应用网关](https://www.janusec.com/) &nbsp; [![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=Protect%20web%20applications%20from%20network%20attacks%20with%20open%20source%20Janusec%20Application%20Gateway&url=https://github.com/Janusec/janusec&via=janusec&hashtags=waf,web,application,firewall,gateway)

[![Build Status](https://travis-ci.org/Janusec/janusec.svg?branch=master)](https://travis-ci.org/Janusec/janusec)


[English Readme](#provide-fast-and-secure-application-delivery)  

## 提供快速、安全的应用交付   

![Janusec Application Gateway](gateway1.png)  

介绍PPT： https://www.janusec.com/download/Janusec-Application-Gateway-CN.pdf   

### 主要功能  

JANUSEC应用网关的主要功能有：  

* 向Web应用提供统一的安全接入，包括HTTPS、身份认证、安全防御（WAF/CC）等。如Web应用是通过K8S Pods部署的，该网关也可以作为K8S Ingress Controller使用，向Pods提供跟普通Web应用同样的接入和安全特性。  

* 向非Web应用提供四层TCP/UDP路由转发（含K8S Pods）  

* 提供ACME自动化证书（免费），用于支持用户HTTPS访问，证书到期时自动续期   

### 主要特性  

* 快速: Web化配置  

* 安全  

  + 安全接入: 一键启用HTTPS   

  + 安全认证:  
      - OAuth2: WxWork(企业微信), DingTalk(钉钉), Feishu(飞书)  
      - LDAP+认证码双因子   
      - CAS 2.0  

  + 安全防御  
      - WAF (Web应用防火墙，拦截SQL注入/XSS/敏感数据泄露等)    
      - 拦截CC攻击  
      - 支持CAPTCHA (验证码)  

  + 安全运维: Web界面执行SSH运维   
 
  + 安全存储: 加密证书私钥  

* 可扩展    
  + 多节点负载均衡   
  + 静态文件缓存加速  



## 截图   

### SQL注入截图  

![Janusec Application Gateway Screenshot](waf-demo1.png)  

### 敏感信息泄露截图  

![Janusec Application Gateway Screenshot](waf-demo2.png)  

## 产品网站   

https://doc.janusec.com/cn/   

## 需求   

* SQLite3，或PostgreSQL 10/11/12/13+ (开发环境，及生产环境主节点需要)  
* Debian 9/10/11+, CentOS/RHEL 7/8+, 首选Debian 10/11+    
* systemd  
* nftables  
* Golang 1.19+ (仅开发环境需要)  

## 部署快速指引    

详细文档可在这里获取： [快速入门](https://doc.janusec.com/cn/quick-start/)  

如希望快速体验，可尝试使用 [Docker镜像](https://doc.janusec.com/cn/appendix-docker/)    

## 开发快速指引   

> git clone https://github.com/Janusec/janusec.git   


编辑`config.json`  

> "host": "127.0.0.1",  
> "port": "5432",  
> "user": "janusec",  
> "password": "123456",  
> "dbname": "janusec"  

Janusec将自动加密数据库口令    
然后:  

> go build  
> su (切换到root)  
> ./janusec  

## Web管理入口 

当config.json中listen=false时 ，使用如下地址:  

> http://`your_primary_node_ip_address`/janusec-admin/    (首次使用)  
> https://`your_application_domain_name`/janusec-admin/   (配置证书后)  

当config.json中listen=true时，使用如下地址:  

> http://`your_primary_node_ip_address:9080`/janusec-admin/    (首次使用)  
> https://`your_primary_node_domain_name:9443`/janusec-admin/  (配置证书和应用后)  

只使用主节点时，任意应用域名均可用于访问管理入口。   
如果使用了副本节点，应为主节点申请一个单独的域名。   

[Janusec应用网关配置](https://doc.janusec.com/cn/quick-start/)   

## 发布 

目前仅支持Linux  

> go build  
> su  
> `./release.sh`    

生成的发布包位于`./dist`目录。    

## Web管理发布

Web化管理所需的文件在 `./static/janusec-admin/` 目录, 源码在 [Janusec-Admin Github](https://github.com/Janusec/janusec-admin) ，前端源码使用Angular 9.  

## 许可证  

Janusec应用网关源文件使用GNU [AGPLv3](http://www.gnu.org/licenses/agpl-3.0.html)授权.    

## 增强特性  

增强体验版是在开源版本基础上进一步增强，增强特性部分不开源，仅用于测试或体验。  

增强特性包括：

* Cookie合规管理(提供Cookie Banner与用户同意管理) ， v1.4.2版本开始提供  
* GSLB (全局负载均衡，自带DNS服务器) ， v1.4.2版本开始提供  

增强体验版的下载链接可以在 [快速入门](https://doc.janusec.com/cn/quick-start/) 找到。   

## 支持  

* 产品网站 [https://doc.janusec.com/cn/](https://doc.janusec.com/cn/)   
* 官方网站: [https://www.janusec.com/](https://www.janusec.com/)  
* Email: `support#janusec.com`  
* QQ群: 776900157  


---  

## Provide Fast and Secure Application Delivery  

![Janusec Application Gateway](gateway1.png)  

Introduction Slides: https://www.janusec.com/download/Janusec-Application-Gateway.pdf   

### Main functions  

The main functions of JANUSEC Application Gateway include:  

* Provide unified security access to web applications, including HTTPS, OAuth Authentication, security defense (WAF/CC), etc. If the web application is deployed through K8S Pods, the gateway can also be used as K8S Ingress Controller to provide Pods with the same access and security features as ordinary web applications.  

* Provide four-tier TCP/UDP forwarding to non-Web applications, including K8S Pods  

* Provide ACME automation certificate (free) for HTTPS access, and automatically renew the certificate when it expires   

### Key Features   

* Fast Delivery : Web-based Configuration    

* Security    

  + Secure Access: Enable HTTPS by One Click   

  + Secure Authentication:  
      - OAuth2: WxWork, DingTalk, Feishu, Lark    
      - LDAP + Authenticator 2FA    
      - CAS 2.0  

  + Secure Defense   
      - WAF (Web Application Firewall), Block SQL Injection, XSS, Sensitive Data leakage etc.    
      - Block CC Attacks  
      - CAPTCHA   

  + Secure Operation: Web SSH Operation    
 
  + Secure Storage: Encryption of Private Key   

* Scalable      
  + Multiple Nodes Load Balance     
  + Static Content Cache and Acceleration    



## Screenshots     

### SQL Injection Screenshot  

![Janusec Application Gateway Screenshot](waf-demo1.png)  

### Sensitive Data Leakage Screenshot   

![Janusec Application Gateway Screenshot](waf-demo2.png)  

## Product Web Site   

English:   
https://janusec.github.io/  


## Requirements    

* SQLite3 or PostgreSQL 10/11/12/13+ (Required by Development and Primary Node of Deployment)  
* Debian 9/10/11+, CentOS/RHEL 7/8+, Debian 10/11+ is preferred       
* systemd  
* nftables  
* Golang 1.19+ (Required by Development Only)  

## Quick Start for Deployment     

Detailed documentation is available at： [Janusec Application Gateway Quick Start](https://janusec.github.io/documentation/quick-start/).  

You can also try it with [Docker Image](https://janusec.github.io/documentation/appendix-docker/)    

## Quick Start for Developer   

> git clone https://github.com/Janusec/janusec.git   


Edit `config.json`     

> "host": "127.0.0.1",  
> "port": "5432",  
> "user": "janusec",  
> "password": "123456",  
> "dbname": "janusec"  

Janusec will encrypt the password automatically, then:  

> go build  
> su (switch to root)  
> ./janusec  

## Web Administration   

When listen=false in config.json:  

> http://`your_primary_node_ip_address`/janusec-admin/    (first use)  
> https://`your_application_domain_name`/janusec-admin/   (after certificate configured)  

When listen=true in config.json :  

> http://`your_primary_node_ip_address:9080`/janusec-admin/    (first use)  
> https://`your_primary_node_domain_name:9443`/janusec-admin/  (after certificate configured)  

When using primary node only, any application domain name can be used for admin.   
But if you have one or more replica nodes, you should apply for a seperate domain name for primary node.   

[Janusec Application Gateway Configuration](https://janusec.github.io/documentation/quick-start/)   

## Release   

Only support Linux Now    

> go build  
> su  
> `./release.sh`    

The release package is under `./dist` .  

## Web Administration Release  

Release directory is `./static/janusec-admin/` , and source code is available at [Janusec-Admin Github](https://github.com/Janusec/janusec-admin) with Angular 9.  

## LICENSE   

Janusec Application Gateway source files are made available under the terms of the GNU Affero General Public License ([GNU AGPLv3](http://www.gnu.org/licenses/agpl-3.0.html)).   

## Professional Plus Edition    

The Professional Plus Edition is a further enhancement based on the open source version. The enhanced features are not open source and are only used for testing or experience.  

Professional features：

* Cookie Compliance Management, include Cookie Banner, Consent Management and Cookie Discovery etc., provided from v1.4.2  
* GSLB (Global Server Load Balance, with DNS Server) , provided from v1.4.2  

The download link is available at： [Quick Start](https://janusec.github.io/documentation/quick-start/).  

## Support   

* Product: [https://janusec.github.io/](https://janusec.github.io/)   
* Official site : [https://www.janusec.com/](https://www.janusec.com/)  
* Email: `support#janusec.com`  
* QQ Group: 776900157 
