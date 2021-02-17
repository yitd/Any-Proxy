# Any-Proxy
Any-Proxy可以帮助你完美地反向代理浏览任意网站，免去复杂的程序，兼容性极好  
  
最新版本将退出指令改成了~q 这将在输入时更加便捷，需配置伪静态，nginx伪静态规则如下：  

```nginx
if ( !-e $request_filename) {  
  rewrite ^/(.*)$ /index.php?$1 last;  
  break;  
}
```

## Features
1. 支持 POST、Cookie，https/http 均可使用  
2. 支持伪造 IP，`$anp->anyIp` 值为 `1` 发送服务器 IP 头，值为 `2` 则发送随机 IP，值为 `3` 发送客户端IP  
3. 已解决中文乱码问题，自动转换  
4. 在当前链接末尾输入 ~q 可以退出当前页面回到首页  
5. 在域名后面加上链接地址即可访问

## File difference
- index.php 外链、外链图片、外链静态文件等请求不通过 Any-Proxy，地址栏不会显示目标域名  
- index_all.php 区别为传统版，地址栏会显示目标域名，性能不及前者  
- index_all.php 所有外链、外链图片、外链静态文件等请求都通过 Any-Proxy

## Demo
https://turl.chat/http://+需访问的链接 （必须添加http(s)://）  
  
> 如：`https://turl.chat/http://ip38.com/`

测试站点请求量超过 50 次将会无法访问

![Image](https://p.pstatp.com/origin/fe81000376fc445be379)  
![Image](https://p.pstatp.com/origin/137b90001905c99862df3)  

## Contributors
[View all contributors](/contributors)

## Creadit
基于：https://github.com/koala0529/reverse-proxy-php 修改  

请勿将本项目用于非法用途，否则后果自负。
