# [Janusec Application Gateway](https://www.janusec.com/) &nbsp; [![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=Protect%20web%20applications%20from%20network%20attacks%20with%20open%20source%20Janusec%20Application%20Gateway&url=https://github.com/Janusec/janusec&via=janusec&hashtags=waf,web,application,firewall,gateway)

[![Build Status](https://travis-ci.org/Janusec/janusec.svg?branch=master)](https://travis-ci.org/Janusec/janusec)

[README](https://github.com/Janusec/janusec) | [README中文版](https://github.com/Janusec/janusec/blob/master/README-CN.md)  

## Build Scalable Application Security Infrastructures  

![Janusec Application Gateway](https://www.janusec.com/images/gateway1.png)  

Janusec Application Gateway, an application security solutions which provides WAF (Web Application Firewall), unified web administration portal, private key protection, web routing and scalable load balancing. With Janusec, you can build secure and scalable applications.  

### Key Features  

* WAF (Web Application Firewall), block SQL Injection, Cross-site Scripting, Sensitive Data Leakage, CC Attacks etc.  
* Group Policy (Cooperation with Multiple Check Points)
* CAPTCHA support  
* Unified Web Administration  
* HTTPS support, No Agent Required.  
* Certificate Protection with Private Key Encrypted Storage  
* Scalable Architecture, Load Balance and Multiple Nodes Support  

## Screenshots  

### SQL Injection Screenshot

![Janusec Application Gateway Screenshot](https://www.janusec.com/images/waf-demo1.png)  

### Sensitive Data Leakage Screenshot

![Janusec Application Gateway Screenshot](https://www.janusec.com/images/waf-demo2.png)  

## Official Web Site  

https://www.janusec.com/  

Detailed documentation is available at [Janusec Application Gateway Documentation](https://www.janusec.com/documentation/quick-start/).

## Requirements  

* PostgreSQL 9.3~9.6 or 10 (Required by Development and Master Node of Deployment)  
* CentOS/RHEL 7, Debian 9  
* systemd  
* Golang 1.9+  

## Quick Start for Deployment  

https://www.janusec.com/documentation/quick-start/

## Quick Start for Developer  

> go get github.com/Janusec/janusec  

Edit config.json with PostgreSQL  

> "host": "127.0.0.1",  
> "port": "5432",  
> "user": "janusec",  
> "password": "123456",  
> "dbname": "janusec"  

Janusec will encrypt the password automatically.  
Then:  

> go build  
> ./janusec  

## Web Administration  

> http://127.0.0.1:9080/  (The first address)  

[Janusec Application Gateway Configuration](https://www.janusec.com/documentation/quick-start/)  

## Release  

> go build  
> `./release.sh`  (Only support Linux Now)  

The release package is under ./dist .

## Web Administration Portal

Release directory is `./static/` , and source code is available at [Janusec-Admin Github](https://github.com/Janusec/janusec-admin) with Angular 5.  

## LICENSE

Janusec Application Gateway source files are made available under the terms of the GNU Affero General Public License ([GNU AGPLv3](http://www.gnu.org/licenses/agpl-3.0.html)).  
