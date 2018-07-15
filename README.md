# Janusec Application Gateway  

## Build Scalable Application Security Infrastructures  

![Janusec Application Gateway](https://www.janusec.com/images/gateway1.png)  

Janusec Application Gateway, an application security solutions for public cloud, private cloud, and traditional IDC, which provides web routing, load balancing, and web application firewall. With Janusec, you can build secure and scalable applications.  

### Key Features  

* WAF (Web Application Firewall), block SQL Injection, Cross-site Scripting, Sensitive Data Leakage, CC Attacks etc.  
* Group Policy (Cooperation with Multiple Check Points)
* CAPTCHA support  
* Unified Web Administration  
* HTTPS support, No Agent Required.  
* Certificate Protection with Private Key Encrypted Storage  
* Scalable Architecture, Load Balance and Multiple Nodes Support  

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

> go get github.com/lib/pq  
> go get github.com/gorilla/sessions  
> go get github.com/dchest/captcha  

Edit config.json with PostgreSQL  

> "host": "127.0.0.1",  
> "port": "5432",  
> "user": "janusec",  
> "password": "123456",  
> "dbname": "janusec"  

Janusec will encrypt the password automatically.  
Then:  

> go build janusec.go  
> ./janusec  

## Web Administration  

> http://127.0.0.1:9080/  (The first address)  

[Janusec Application Gateway Configuration](https://www.janusec.com/documentation/quick-start/)  

## Release  

> ./release.sh  

The release package is under ./dist .

## Web Administration Portal

Release directory is `./static/` , and source code is available at [Janusec-Admin Github](https://github.com/Janusec/janusec-admin) with Angular 5.  

## LICENSE

Janusec Application Gateway source files are made available under the terms of the GNU Affero General Public License ([GNU AGPLv3](http://www.gnu.org/licenses/agpl-3.0.html)).  
