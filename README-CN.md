# [Janusec应用网关](https://www.janusec.com/cn/)  

[README](https://github.com/Janusec/janusec) | [README中文版](https://github.com/Janusec/janusec/blob/master/README-CN.md)  

## 构建可扩展的应用安全基础设施  

![Janusec应用网关](https://www.janusec.com/images/gateway1.png)  

Janusec应用网关(Janusec Application Gateway)，提供WAF (Web Application Firewall, Web应用防火墙)、统一Web化管理入口、证书私钥保护，Web路由以及可扩展的负载均衡等功能，是应用安全领域的最佳实践。  

### 主要特性  

* WAF (Web应用防火墙), 拦截SQL Injection, XSS, 敏感数据泄露, CC攻击等  
* 组合策略 (多检查点联动，如请求和响应联动)
* 验证码（CAPTCHA）支持  
* 统一的Web化管理入口  
* 支持HTTPS, 不需要Agent  
* 证书私钥加密存储  
* 可扩展，负载均衡  

## 截图  

### SQL注入截图

![Janusec Application Gateway Screenshot](https://www.janusec.com/images/waf-demo1.png)  

### 敏感信息泄露截图

![Janusec Application Gateway Screenshot](https://www.janusec.com/images/waf-demo2.png)  


## 官方网站  

https://www.janusec.com/  

详细文档可在这里获取 [Janusec应用网关快速入门](https://www.janusec.com/cn/quick-start/).

## 需求  

* PostgreSQL 9.3~9.6 or 10 (开发环境需要，生产环境仅主节点需要)  
* CentOS/RHEL 7, Debian 9  
* systemd  
* Golang 1.9+ (开发环境需要，生产环境不需要)  

## 快速启动入门指引  

https://www.janusec.com/cn/quick-start/

## 开发者快速启动  

> go get -u github.com/Janusec/janusec  
> cd $GOPATH/src/github.com/Janusec/janusec  

编辑 config.json 中的 PostgreSQL 设置  

> "host": "127.0.0.1",  
> "port": "5432",  
> "user": "janusec",  
> "password": "123456",  
> "dbname": "janusec"  

Janusec将自动加密数据库口令，然后：  

> go build  
> su (切换到root用户)  
> ./janusec  

## Web化管理  

> http://127.0.0.1:9080/  (首次使用地址)  

[Janusec应用网关配置](https://www.janusec.com/cn/quick-start/)  

## 发布  

> go build  
> su  
> ./release.sh (暂只支持在Linux环境运行)  

发布包在 ./dist目录下.

## Web化管理相关文件

Web化管理所需的文件在 `./static/` 目录, 源码在 [Janusec-Admin Github](https://github.com/Janusec/janusec-admin) ，前端源码使用Angular 5.  

## LICENSE

Janusec应用网关源文件使用GNU [AGPLv3](http://www.gnu.org/licenses/agpl-3.0.html)授权.  

## Support

* 官方网站: [https://www.janusec.com/](https://www.janusec.com/)  
* 镜像网站: [https://janusec.github.io/](https://janusec.github.io/)  
* Email: `support#janusec.com`  
* QQ群: 776900157  , @[U2](https://github.com/zhyale) (作者)  
