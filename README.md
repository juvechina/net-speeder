# net-speeder ipv6与发包倍数支持版
net-speeder 在高延迟不稳定链路上优化单线程下载速度 
# 本版本是AI生成的支持ipv6和发包数量的版本 已在debian上测试通过

项目由https://code.google.com/p/net-speeder/  迁入
关注微信公众号了解最新开发进度/获取帮助/提出建议：
<img src="http://www.snooda.com/images/qrcode.jpg" />
A program to speed up single thread download upon long delay and unstable network
在高延迟不稳定链路上优化单线程下载速度

注1：开启了net-speeder的服务器上对外ping时看到的是4倍，实际网络上是2倍流量。另外两倍是内部dup出来的，不占用带宽。
另外，内部dup包并非是偷懒未判断。。。是为了更快触发快速重传的。
注2：net-speeder不依赖ttl的大小，ttl的大小跟流量无比例关系。不存在windows的ttl大，发包就多的情况。

# 安装步骤：

# 1：下载源码并解压
    wget https://github.com/snooda/net-speeder/archive/master.zip
    unzip master.zip
    替换 net_speeder.c 文件

# 2：准备编译环境
#先清理旧版本的libnet
## 1. 彻底清除所有 apt 版本的 libnet
    sudo apt-get purge -y libnet1-dev libnet-dev
    sudo apt-get autoremove -y

## 2. 彻底删除 /usr/local/ 中的残留
    sudo rm -f /usr/local/include/libnet.h
    sudo rm -f /usr/local/bin/libnet-config
    sudo rm -f /usr/local/lib/libnet.so*
    sudo rm -f /usr/local/lib/libnet.a
    sudo rm -f /usr/local/lib/pkgconfig/libnet.pc

## 3. 编译安装libnet1.3 支持ipv6的必要库
    wget https://github.com/libnet/libnet/releases/download/v1.3/libnet-1.3.tar.gz
    tar -xzvf libnet-1.3.tar.gz
    cd libnet-1.3/
    ./configure
    make
    sudo make install
    sudo ldconfig

## 4. 编译其他依赖
    #debian/ubuntu：
    sudo apt-get update
    sudo apt-get install -y build-essential wget
    #安装libpcap-dev：
    apt-get install libpcap0.8-dev 

    #centos：
    yum -y install epel-release
    #然后即可使用yum安装：
    yum install libpcap libpcap-devel

## 5. 编译：

    #Linux Cooked interface使用编译（venetX，OpenVZ）：
    gcc -O2 -DCOOKED -o net_speeder net_speeder.c -lpcap -lnet

    #普通网卡使用编译（Xen，KVM，物理机）：
    gcc -O2 -o net_speeder net_speeder.c -lpcap -lnet

## 6. 使用方法(需要root权限启动）：
    sudo ./net_speeder eth0 "ip"
    sudo ./net_speeder eth0 "ip6"
    sudo ./net_speeder eth0 "ip or ip6"
    # 增加发包倍数 为2倍发包：
    sudo ./net_speeder eth0 "ip" 2 
## 7.异常处理：
    如果kvm下报错：err msg:[libnet_write_raw_ipv4(): -1 bytes written (Message too long)
    #关闭tso
    ethtool -K 网卡名 tso off
    
    #Centos7运行时 如果报错：
    error while loading shared libraries: libnet.so.9: cannot open shared object file: No such file or directory
    # 安装 libnet
    sudo yum install -y libnet libnet-devel
    # 如果找到 libnet.so.1，创建符号链接
    sudo ln -s /usr/lib/libnet.so.1 /usr/lib/libnet.so.9
    # 或者 64 位系统
    sudo ln -s /usr/lib64/libnet.so.1 /usr/lib64/libnet.so.9
    # 或者
    sudo ln -s /usr/lib/x86_64-linux-gnu/libnet.so.1 /usr/lib/x86_64-linux-gnu/libnet.so.9
    # 更新动态链接库缓存
    sudo ldconfig
    # 建议centos7用户尽快换装ubuntu24.04 获取更新内核以及更好的bbr加速效果
## 7. 注意事项：
不建议增加发包倍数，默认的即可；
对于网络非常差的，增加发包效果也不是很明显，发包越多实际延迟也会增加，带宽也会增加很多额外开销；
请务必合法使用：仅用于自己的网络环境测试，请遵守当地法律
