# azure-http-proxy [![Build Status](https://travis-ci.org/lxrite/azure-http-proxy.svg?branch=master)](https://travis-ci.org/lxrite/azure-http-proxy)

## 简介

AHP(Azure Http Proxy)是一款高速、安全、轻量级和跨平台的HTTP代理，使用对称加密算法AES对传输的数据进行加密，使用非对称加密算法RSA传输密钥。

## 特性
 - 一连接一密钥，AHP会对每个连接使用一个随机生成的密钥和初始化向量，避免重复使用同一密钥
 - 使用非对称加密算法RSA传输密钥，只需对客户端公开RSA公钥
 - 对目标域名的解析在服务端进行，可以解决本地DNS污染的问题
 - 服务端同时支持多种数据加密方式，数据加密方式可由客户端任意指定，客户端可以权衡机器性能以及安全需求选择合适的加密方式
 - 多线程并发处理，充分利用多处理器的优势，能同时处理成千上万的并发连接
 - 多用户支持，允许为每个用户使用独立的帐号和密码

## 新增特性
可指定配置文件，允许一台机器运行多个实例；允许使用单独使用Asio的standalone模式，或者使用依赖于boost的模式，开关选项在CMakeLists.txt 中指定。如果指定了单独模式，请修改对应的asio路径。

## 编译和安装

Windows平台可以从 https://github.com/lxrite/azure-http-proxy/releases 下载已经编译好的(win32-binary.zip)。

### 编译器

AHP使用了部分C++11/14/17特性，所以对编译器的版本有较高要求，下面列出了部分已测试过可以用来编译AHP的编译器

 - Microsoft Visual Studio >= 2015
 - GCC >= 7.3.1
 - Clang >= 4
 - MinGW >= 4.9
09b7a6004ed6eeb90b27d5f4da7fc682bcc2c023 这个版本不需要c++17，如果编译器无法升级的话，请checkout这个版本。
参考：http://en.cppreference.com/w/cpp/compiler_support
###本版本修改
我的版本将原始版本对boost::any boost::optional的依赖都去除了，同时将原来的json依赖替换为了nlohmann 的json，https://github.com/nlohmann/json。
引入spdlog进行log追踪，系统自带的spdlog 版本是master版，与当前代码所用spdlog不匹配，需要使用者自行去github下载对应的develop版本 https://github.com/gabime/spdlog
stand_alone的asio 也可以去github下载，https://github.com/chriskohlhoff/asio
### 安装依赖

AHP依赖OpenSSL库

绝大多数Linux发行版都可以通过包管理安装OpenSSL

#### Ubuntu

    $ apt-get install libssl-dev

#### Fedora
    $ yum install openssl
    $ yum install openssl-devel

Windows OpenSSL库可以从 https://slproweb.com/products/Win32OpenSSL.html 下载到编译好的。

### 编译
AHP使用自动化构建工具CMake来实现跨平台构建，构建时选择是否单独使用`ASIO`,如果使用这种模式请修改`CMakelist.txt`文件中`ASIO_DIR`的路径。

 - CMake >= 2.8

Windows下可以使用cmake-gui.exe，Linux或其他类Unix系统可以使用下面的命令编译

    $ cd azure-http-proxy
    $ mkdir build
    $ cd build
    $ cmake ..
    $ make

如果编译成功会生成ahpc（客户端）和ahps（服务端）。
## 配置和运行

完整的配置示例见这里： https://github.com/lxrite/azure-http-proxy/tree/master/example

注意：不要使用示例配置中的RSA私钥和公钥，因为私钥一公开就是不安全的了。

如果你要运行的是服务端，那么你首先需要生成一对RSA密钥对，AHP支持任意长度不小于1024位的RSA密钥。下面的命令使用openssl生成2048位的私钥和公钥

    $ openssl genrsa -out rsa_private_key.pem 2048
    $ openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem

服务端保留私钥并将公钥告诉客户端。

### 配置服务端 
服务端默认配置文件为`server.json`，同时用户可提供其他文件作为命令行参数输入。注意最好将该文件放在当前可执行文件的相同目录下，如果是不同目录可能会崩溃。
下面是一个配置文件的样本：

    {
      "bind_address": "0.0.0.0",
      "listen_port": 8090,
      "rsa_private_key": "-----BEGIN RSA PRIVATE KEY----- ...... -----END RSA PRIVATE KEY-----",
      "timeout": 240,
      "workers": 4,
      "auth": true,
      "users": [
        {
          "username": "username1",
          "password": "password1"
        },
        {
          "username": "foobar",
          "password": "bazqux"
        }
      ]，
	  "log_level": "info",
	  "console_log_level": "warning",
	  "file_log_level": "info"
    }

字段名          | 描述               | 是否必选         | 默认值    |
----------------|--------------------|------------------|-----------|
bind_address    | 服务端绑定的IP地址 | 否               | "0.0.0.0" |
listen_port     | 服务端绑定的端口   | 否               | 8090      |
rsa_private_key | RSA私钥            | 是               | 无        |
timeout         | 超时时间（秒）     | 否               | 240       |
workers         | 并发工作线程数     | 否               | 4         |
auth            | 启用代理身份验证   | 否               | false     |
users           | 用户列表           | auth为true时必选 | 无        |
log_level       | 日志等级           | 否               | off        |
console_log_level       | 控制台输出日志等级           | 否               | off        |
file_log_level       | 文件输出日志等级           | 否               | off        |

如果是监听`ipv6`地址的话，则需要在地址那里填写"::"
### 配置客户端

客户端默认配置文件为`client.json`，用户也可在命令行指定文件。与服务器配置文件一样，最好把配置文件放在可执行文件的同一目录下。
下面是客户端配置文件示例：

    {
      "proxy_server_address": "127.0.0.1",
      "proxy_server_port": 8090,
      "bind_address": "127.0.0.1",
      "listen_port": 8089,
      "rsa_public_key": "-----BEGIN PUBLIC KEY----- ...... -----END PUBLIC KEY-----",
      "cipher": "aes-256-ofb",
      "timeout": 240,
      "workers": 2,
	 "log_level": "info",
	  "console_log_level": "warning",
	  "file_log_level": "info"
    }

字段名               | 描述                 | 是否必选         | 默认值        |
---------------------|----------------------|------------------|---------------|
proxy_server_address | 服务端的IP地址或域名 | 是               | 无            |
proxy_server_port    | 服务端的端口         | 是               | 无            |
bind_address         | 客户端绑定的IP地址   | 否               | "127.0.0.1"   |
listen_port          | 客户端的监听端口     | 否               | 8089          |
rsa_public_key       | RSA公钥              | 是               | 无            |
cipher               | 加密方法             | 否               | "aes-256-ofb" |
timeout              | 超时时间（秒）       | 否               | 240           |
workers              | 并发工作线程数       | 否               | 2             |
log_level       | 日志等级           | 否               | off        |
console_log_level       | 控制台输出日志等级           | 否               | off        |
file_log_level       | 文件输出日志等级           | 否               | off        |

#### 支持的加密方法

 - aes-xyz-cfb
 - aes-xyz-cfb8
 - aes-xyz-cfb1
 - aes-xyz-ofb
 - aes-xyz-ctr

中间的xyz可以为128、192或256。

## 运行

确定配置无误后就可以运行AHP了。

### 运行服务端

 Linux或其他类Unix系统
 
    $ ./ahps [配置文件名称]
 
 Windows
 
    $ ahps.exe [配置文件名称]
 
### 运行客户端

Linux或其他类Unix系统

    $ ./ahpc [配置文件名称]
 
Windows
 
    $ ahpc.exe [配置文件名称]
 
 Enjoy!
 
