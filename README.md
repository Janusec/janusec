# Janusec Application Gateway / JANUSEC应用网关  

[![Build Status](https://travis-ci.org/Janusec/janusec.svg?branch=master)](https://travis-ci.org/Janusec/janusec)


[English Readme](#provide-fast-and-secure-application-delivery)  

## 提供快速、安全的应用交付   

![Janusec Application Gateway](gateway1.png)  

介绍PPT： https://www.janusec.com/download/Janusec-Application-Gateway-CN.pdf   


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

https://janusec.github.io/cn/   


## 需求   

* PostgreSQL 10/11/12/13/14+ (开发环境，及生产环境主节点需要)  
* Debian 9/10/11+, CentOS/RHEL 7/8+, 首选Debian 10+    
* systemd  
* nftables  
* Golang 1.15+ (仅开发环境需要)  

## 部署快速指引    

详细文档可在这里获取： [Janusec应用网关快速入门](https://janusec.github.io/cn/quick-start/)  

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

[Janusec应用网关配置](https://janusec.github.io/cn/quick-start/)   

## 发布 

目前仅支持Linux  

> go build  
> su  
> `./release.sh`    

生成的发布包位于`./dist`目录。    

## Web管理发布

Web化管理所需的文件在 `./static/janusec-admin/` 目录, 源码在 [Janusec-Admin Github](https://github.com/Janusec/janusec-admin) ，前端源码使用Angular 9.  

## 多许可证  

JANUSEC应用网关开源版本的源文件使用GNU [AGPLv3](http://www.gnu.org/licenses/agpl-3.0.html)授权.     
专业增强特性版本闭源发布，增强特性包括：GSLB、Cookie合规（应用无需修改）等。   

## 支持  

* 产品网站 [https://janusec.github.io/cn/](https://janusec.github.io/cn/)   
* Email: `support`**@**`janusec.com`  
* QQ群: 776900157  


---  

## Provide Fast and Secure Application Delivery  

![Janusec Application Gateway](gateway1.png)  

Introduction Slides: https://www.janusec.com/download/Janusec-Application-Gateway.pdf   

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

* PostgreSQL 10/11/12/13/14+ (Required by Development and Primary Node of Deployment)  
* Debian 9/10/11+, CentOS/RHEL 7/8+, Debian 10+ is preferred       
* systemd  
* nftables  
* Golang 1.15+ (Required by Development Only)  

## Quick Start for Deployment     

Detailed documentation is available at： [Janusec Application Gateway Quick Start](https://janusec.github.io/documentation/quick-start/).   

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
But if you have one or more replica nodes, you should apply for a separate domain name for primary node.   

[Janusec Application Gateway Configuration](https://janusec.github.io/documentation/quick-start/)   

## Release   

Only support Linux Now    

> go build  
> su  
> `./release.sh`    

The release package is under `./dist` .  

## Web Administration Release  

Release directory is `./static/janusec-admin/` , and source code is available at [Janusec-Admin Github](https://github.com/Janusec/janusec-admin) with Angular 9.  

## Multiple LICENSES   

The open source files are made available under the terms of the GNU Affero General Public License ([GNU AGPLv3](http://www.gnu.org/licenses/agpl-3.0.html)).   

The professional enhanced version is released in closed source, and the enhanced features including GSLB, Cookie compliance (No need to modify applications), etc.   

## Support   

* Product: [https://janusec.github.io/](https://janusec.github.io/)    
* Email: `support`**@**`janusec.com`  
* QQ Group: 776900157 
