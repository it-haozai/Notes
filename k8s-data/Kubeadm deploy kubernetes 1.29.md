# Kubeadm Deploy Kubernetes 1.29

[TOC]

## 1.`Kubeadm` 相关介绍

`kubeadm`是`Kubernetes`官方提供的用于快速安部署`Kubernetes`集群的工具，伴随`Kubernetes`每个版本的发布都会同步更新，`kubeadm`会对集群配置方面的一些实践做调整，通过实验`kubeadm`可以学习到`Kubernetes`官方在集群配置上一些新的最佳实践。

## 2.主机硬件配置

| System     | Hostname  | IPservice      | service  | cpu&memory |
| ---------- | --------- | -------------- | -------- | ---------- |
| rocky-8.10 | master-01 | 192.168.110.10 | Nginx,LB | 2c&4m      |
| rocky-8.10 | master-02 | 192.168.110.11 | Nginx,LB | 2c&4m      |
| rocky-8.10 | master-03 | 192.168.110.12 | Nginx    | 2c&4m      |
| rocky-8.10 | node-01   | 192.168.110.13 |          | 4c&8m      |
| rocky-8.10 | node-02   | 192.168.110.14 |          | 4c&8m      |

## 3.系统环境配置（所有主机）

###  配置主机的`Hosts`

```shell
cat << EOF | tee /etc/hosts
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
192.168.110.10 master-01
192.168.110.11 master-02
192.168.110.12 master-03
192.168.110.13 node-01
192.168.110.14 node-02
EOF
```

### 关闭`Selinx`与`firewalld`

#### `selinx`

```shell
setenforce 0
sudo sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
```

#### `firewalld`

```shell
systemctl stop firewalld.service
systemctl disable firewalld.service
```

### 关闭`Swap`分区

```shell
swapoff -a
```

> 修改`/etc/fstab`文件，注释掉 `SWAP` 的自动挂载，使用`free -m`确认`swap`已经关闭

![image-20240902141605073](https://raw.githubusercontent.com/it-haozai/Pictures/main/img/image-20240902141605073.png)



## 4.`Chrony` 时间同步（所有机器）

### 安装`Chrony`服务

```shell
yum install chrony -y
```

### 修改`Chrony config`文件

```shell
cat > /etc/chrony.conf << EOF
# Use NTP servers from Alibaba Cloud and Tsinghua University.
server ntp1.aliyun.com iburst
server ntp2.aliyun.com iburst
server ntp3.aliyun.com iburst
server ntp4.aliyun.com iburst
server ntp.tuna.tsinghua.edu.cn iburst
# Record the rate at which the system clock gains/losses time.
driftfile /var/lib/chrony/drift
# Allow the system clock to be stepped in the first three updates
# if its offset is larger than 1 second.
makestep 1.0 3
# Enable kernel synchronization of the real-time clock (RTC).
rtcsync
# Specify file containing keys for NTP authentication.
keyfile /etc/chrony.keys
# Get TAI-UTC offset and leap seconds from the system tz database.
leapsectz right/UTC
# Specify directory for log files.
logdir /var/log/chrony
EOF
```

### 启动`Chrony`服务

```shell
systemctl enable --now chronyd && systemctl status chronyd.service
```

### 开启`Chrony NTP`同步

```shell
timedatectl set-ntp true
```

### 验证时间同步状态

```shell
chronyc sources -v
```

### 手动同步时间

```shell
sudo chronyc -a makestep
```

## 5.转发`IPv4`并让`iptables`看到桥接流量

### 加载`overlay`和`br_netfilter`模块

```shell
cat << EOF | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF
```

### 验证模块是否生效

```shell
sudo modprobe overlay
sudo modprobe br_netfilter
```

### 设置所需的 `sysctl` 参数

```shell
cat << EOF | tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
```

### 将读取到的参数值应用到当前的内核中

```shell
sysctl --system
```

### 运行指令确认`br_netfilter`和`overlay`模块被加载

```shell
lsmod | grep br_netfilter && lsmod | grep overlay
```

> 通过运行以下指令确认`net.bridge.bridge-nf-call-iptables`、`net.bridge.bridge-nf-call-ip6tables`和`net.ipv4.ip_forward`系统变量在你的 `sysctl` 配置中被设置为（1）

```shell
sysctl net.bridge.bridge-nf-call-iptables net.bridge.bridge-nf-call-ip6tables net.ipv4.ip_forward
```

## 6.部署`Nginx`+`Keepalived`高可用负载均衡器

![image-20240902141523035](https://raw.githubusercontent.com/it-haozai/Pictures/main/img/image-20240902141523035.png)

### 安装`epel-release`

```shell
 yum install epel-release -y
```

### 安装`Nginx and Keepalived`

> msater-01 Nginx，LB
>
> msater-02 Nginx，LB
>
> msater-03 Nginx

```shell
 yum install nginx keepalived nginx-mod-stream  -y
```

### 修改`Nginx`的`config`文件

```shell
sudo tee /etc/nginx/nginx.conf << EOF
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;
include /usr/share/nginx/modules/*.conf;
events {
    worker_connections 4096;  # 增加到支持更多并发连接
    multi_accept on;          # 尽可能多地接受连接
    use epoll;                # 使用高效的事件处理方法
}
# 四层负载均衡，用于Kubernetes API server
stream {
    log_format  main  '$remote_addr $upstream_addr - [$time_local] $status $upstream_bytes_sent';
    access_log  /var/log/nginx/k8s-access.log  main;
    upstream k8s-apiserver {
       server 192.168.110.10:6443;   # Master1 APISERVER IP:PORT
       server 192.168.110.11:6443;   # Master2 APISERVER IP:PORT
       server 192.168.110.12:6443;   # Master3 APISERVER IP:PORT
    }
    server {
       listen 8443 reuseport;      # 启用reuseport以提高负载分配
       proxy_pass k8s-apiserver;
       proxy_timeout 30s;          # 设置上游连接的超时时间
       proxy_connect_timeout 10s;  # 连接上游的超时时间
    }
}
EOF
```

### 启动`Nginx`服务

```shell
systemctl enable --now nginx && systemctl status nginx
```

### 配置`Keepalived`（主）

```shell
cat > /etc/keepalived/keepalived.conf << EOF
! Configuration File for keepalived
vrrp_script check_nginx {
    script "/etc/keepalived/check_nginx.sh"
}
vrrp_instance VI_1 {
    state MASTER
    interface ens33
    virtual_router_id 51
    priority 100
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    virtual_ipaddress {
       192.168.110.254/24
    }
    track_script {
        check_nginx
    }
}
EOF
```

### 健康检查脚本

```shell
cat > /etc/keepalived/check_nginx.sh << EOF
#!/bin/bash
# 尝试使用 nc 检查 Nginx 服务是否可用
nc -z localhost 8443 > /dev/null 2>&1
# 检查 nc 命令的退出状态码
if [ $? -ne 0 ]; then
    # 如果 Nginx 不响应，尝试启动 Nginx 服务
    systemctl start nginx.service
    sleep 1
    # 再次检查 Nginx 是否可以访问
    nc -z localhost 8443 > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        # 如果 Nginx 仍然无法访问，停止 Keepalived 服务
        systemctl stop keepalived.service
    fi
fi
EOF	
```

### 安装`NC`工具

```shell
yum -y install nc
```

### 脚本设置可执行权限

```
chmod +x /etc/keepalived/check_nginx.sh
```

### 配置`keepalived`（从）

```
cat > /etc/keepalived/keepalived.conf << EOF
! Configuration File for keepalived
vrrp_instance VI_1 {
    state BACKUP
    interface ens33
    virtual_router_id 51
    priority 99
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    virtual_ipaddress {
       192.168.110.254/24
    }
}
EOF
```

启动`keepalived`服务

```shell
systemctl enable --now keepalived && systemctl status keepalived
```

## 7.部署ETCD服务

```shell
mkdir /soft && cd /soft
```

### 下载自签名证书工具

```shell
wget https://pkg.cfssl.org/R1.2/cfssl_linux-amd64
wget https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
wget https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64
```

### 赋予可执行权限

```
chmod +x cfssl_linux-amd64 cfssljson_linux-amd64 cfssl-certinfo_linux-amd64
```

```shell
mv cfssl_linux-amd64 /usr/local/bin/cfssl
mv cfssljson_linux-amd64 /usr/local/bin/cfssljson
mv cfssl-certinfo_linux-amd64 /usr/bin/cfssl-certinfo
```

### `CA`证书配置

```shell
mkdir /root/etcd && cd /root/etcd
```

```shell
cat << EOF | tee ca-config.json
{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "www": {
         "expiry": "87600h",
         "usages": [
            "signing",
            "key encipherment",
            "server auth",
            "client auth"
        ]
      }
    }
  }
}
EOF
```

创建`CA`请求文件

```shell
cat << EOF | tee ca-csr.json
{
    "CN": "etcd CA",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Beijing",
            "ST": "Beijing"
        }
    ]
}
EOF
```

### 创建`ETCD`证书请求文件

> 将所有 `Master IP` 加入到 `CSR` 文件中

```shell
cat << EOF | tee server-csr.json
{
    "CN": "etcd",
    "hosts": [
    "master-01",
    "master-02",
    "master-03",
    "192.168.110.10",
    "192.168.110.11",
    "192.168.110.12",
    "192.168.110.254"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Beijing",
            "ST": "Beijing"
        }
    ]
}
EOF
```

### 生成`CA`证书

```shell
[root@master-01 etcd]# cfssl gencert -initca ca-csr.json | cfssljson -bare ca –
[root@master-01 etcd]# ll
total 24
-rw-r--r-- 1 root root  287 Aug  7 10:12 ca-config.json
-rw-r--r-- 1 root root  956 Aug  7 10:13 ca.csr
-rw-r--r-- 1 root root  209 Aug  7 10:13 ca-csr.json
-rw------- 1 root root 1675 Aug  7 10:13 ca-key.pem
-rw-r--r-- 1 root root 1265 Aug  7 10:13 ca.pem
-rw-r--r-- 1 root root  367 Aug  7 10:13 server-csr.json
```

### 生成`ETCD`证书

```shell
[root@master-01 etcd]# cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=www server-csr.json | cfssljson -bare server
[root@master-01 etcd]# ll
total 36
-rw-r--r-- 1 root root  287 Aug  7 10:12 ca-config.json
-rw-r--r-- 1 root root  956 Aug  7 10:13 ca.csr
-rw-r--r-- 1 root root  209 Aug  7 10:13 ca-csr.json
-rw------- 1 root root 1675 Aug  7 10:13 ca-key.pem
-rw-r--r-- 1 root root 1265 Aug  7 10:13 ca.pem
-rw-r--r-- 1 root root 1066 Aug  7 10:14 server.csr
-rw-r--r-- 1 root root  367 Aug  7 10:13 server-csr.json
-rw------- 1 root root 1679 Aug  7 10:14 server-key.pem
-rw-r--r-- 1 root root 1391 Aug  7 10:14 server.pem
```

### 下载`ETCD`二进制文件

```shell
cd /soft
wget https://github.com/etcd-io/etcd/releases/download/v3.5.12/etcd-v3.5.12-linux-amd64.tar.gz
```

```shell
tar -xvf etcd-v3.5.12-linux-amd64.tar.gz
cp -p etcd-v3.5.12-linux-amd64/etcd* /usr/local/bin/
for i in master-02 master-03;do scp /usr/local/bin/etc* $i:/usr/local/bin/;done
```

### 创建`ETCD`配置文件

```shell
cat > /etc/etcd/cfg/etcd.conf << EOF
#[Member]
ETCD_NAME="master-01"
ETCD_DATA_DIR="/var/lib/etcd/default.etcd"
ETCD_LISTEN_PEER_URLS="https://192.168.110.10:2380"
ETCD_LISTEN_CLIENT_URLS="https://192.168.110.10:2379,http://192.168.110.10:2390"
#[Clustering]
ETCD_INITIAL_ADVERTISE_PEER_URLS="https://192.168.110.10:2380"
ETCD_ADVERTISE_CLIENT_URLS="https://192.168.110.10:2379"
ETCD_INITIAL_CLUSTER="master-01=https://192.168.110.10:2380,master-02=https://192.168.110.11:2380,master-03=https://192.168.110.12:2380"
ETCD_INITIAL_CLUSTER_TOKEN="etcd-cluster"
ETCD_ENABLE_V2="true"
EOF
```

> ETCD_NAME 节点名称, 如果有多个节点, 那么每个节点要修改为本节点的名称。
> ETCD_DATA_DIR 数据目录
> ETCD_LISTEN_PEER_URLS 集群通信监听地址
> ETCD_LISTEN_CLIENT_URLS 客户端访问监听地址
> ETCD_INITIAL_ADVERTISE_PEER_URLS 集群通告地址
> ETCD_ADVERTISE_CLIENT_URLS 客户端通告地址
> ETCD_INITIAL_CLUSTER 集群节点地址,如果多个节点那么逗号分隔
> ETCD_INITIAL_CLUSTER="master-01=https://192.168.110.10:2380,master-02=https://192.168.110.11:2380,master-03=https://192.168.110.12:2380"
> ETCD_INITIAL_CLUSTER_TOKEN 集群Token
> ETCD_INITIAL_CLUSTER_STATE 加入集群的当前状态，new是新集群，existing表示加入已有集群

### 创建`ETCD`的系统启动服务

```shell
cat > /usr/lib/systemd/system/etcd.service << EOF
[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target
[Service]
Type=notify
EnvironmentFile=/etc/etcd/cfg/etcd.conf
ExecStart=/usr/local/bin/etcd \
--initial-cluster-state=new \
--cert-file=/etc/etcd/ssl/server.pem \
--key-file=/etc/etcd/ssl/server-key.pem \
--peer-cert-file=/etc/etcd/ssl/server.pem \
--peer-key-file=/etc/etcd/ssl/server-key.pem \
--trusted-ca-file=/etc/etcd/ssl/ca.pem \
--peer-trusted-ca-file=/etc/etcd/ssl/ca.pem
Restart=on-failure
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
```

### 复制`ETCD`证书到个节点

```shell
mkdir -p /etc/etcd/ssl/
cp /root/etcd/*pem /etc/etcd/ssl/ -rf
```

```shell
for i in master-02 master-03;do ssh $i mkdir -p /etc/etcd/{cfg,ssl};done
for i in master-02 master-03;do scp /etc/etcd/ssl/* $i:/etc/etcd/ssl/;done
for i in master-02 master-03 ;do echo $i "------>"; ssh $i ls /etc/etcd/ssl;done
```

### 启动`ETCD`节点

```shell
systemctl daemon-reload && systemctl enable etcd
systemctl start etcd && systemctl status etcd
```

### 验证`ETCD`集群节点

```shell
ETCDCTL_API=3 /usr/local/bin/etcdctl \
--write-out=table --cacert=/etc/etcd/ssl/ca.pem \
--cert=/etc/etcd/ssl/server.pem \
--key=/etc/etcd/ssl/server-key.pem \
--endpoints="https://192.168.110.10:2379,https://192.168.110.11:2379,https://192.168.110.12:2379" \
endpoint health
```

## 8.部署容器运行时`Containerd`

> 1. 在各个服务器节点上安装容器运行时`Containerd`
>
> 2. 下载`Containerd`的二进制包， 需要注意`cri-containerd-(cni-)-VERSION-OS-ARCH.tar.gz`发行包自`containerd 1.6`版本起已经被弃用，在某些 `Linux` 发行版上无法正常工作，并将在`containerd 2.0`版本中移除，这里下载`containerd-<VERSION>-<OS>-<ARCH>.tar.gz`的发行包，后边再单独下载安装`runc`和`CNI plugins`

### 下载`Containerd`二进制文件

```shell
wget https://github.com/containerd/containerd/releases/download/v1.7.11/containerd-1.7.11-linux-amd64.tar.gz
```

> 将其解压缩到`/usr/local`：

```shell
tar Cxzvf /usr/local containerd-1.7.11-linux-amd64.tar.gz
bin/
bin/containerd-shim-runc-v2
bin/ctr
bin/containerd-shim
bin/containerd-shim-runc-v1
bin/containerd-stress
bin/containerd
```

### 下载`runc`二进制文件

接下来从`runc`的`github`上单独下载安装`runc`，该二进制文件是静态构建的，并且应该适用于任何`Linux`发行版

```shell
wget https://github.com/opencontainers/runc/releases/download/v1.1.9/runc.amd64
install -m 755 runc.amd64 /usr/local/sbin/runc
```

### 生成`Containerd`配置文件

> 根据文档[Container runtimes](https://kubernetes.io/docs/setup/production-environment/container-runtimes/)中的内容，对于使用`systemd`作为`init system`的`Linux`的发行版，使用`systemd`作为容器的`cgroup driver`可以确保服务器节点在资源紧张的情况更加稳定，因此这里配置各个节点上`containerd`的`cgroup driver`为`systemd`

```shell
mkdir -p /etc/containerd
containerd config default > /etc/containerd/config.toml
```

### 修改`Containerd`配置文件

> 修改生成的配置文件`/etc/containerd/config.toml`

```shell
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  ...
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
    SystemdCgroup = true
```

> 再修改`/etc/containerd/config.toml`中的沙箱的镜像

```shell
[plugins."io.containerd.grpc.v1.cri"]
  ...
  # sandbox_image = "registry.k8s.io/pause:3.8"
  sandbox_image = "registry.aliyuncs.com/google_containers/pause:3.9"
```

### 启动`Containerd`服务

> `https://raw.githubusercontent.com/containerd/containerd/main/containerd.service`下载`containerd.service`单元文件，并将其放置在` /etc/systemd/system/containerd.service`

```shell
cat << EOF > /etc/systemd/system/containerd.service
[Unit]
Description=containerd container runtime
Documentation=https://containerd.io
After=network.target local-fs.target

[Service]
ExecStartPre=-/sbin/modprobe overlay
ExecStart=/usr/local/bin/containerd

Type=notify
Delegate=yes
KillMode=process
Restart=always
RestartSec=5

# Having non-zero Limit*s causes performance problems due to accounting overhead
# in the kernel. We recommend using cgroups to do container-local accounting.
LimitNPROC=infinity
LimitCORE=infinity

# Comment TasksMax if your systemd version does not supports it.
# Only systemd 226 and above support this version.
TasksMax=infinity
OOMScoreAdjust=-999

[Install]
WantedBy=multi-user.target
EOF
```

> 配置containerd开机启动，并启动containerd，执行以下命令

```shell
systemctl daemon-reload && systemctl enable --now containerd 
systemctl status containerd
```

### 安装`crictl`工具

```shell
wget https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.29.0/crictl-v1.29.0-linux-amd64.tar.gz
```

```shell
tar -zxvf crictl-v1.29.0-linux-amd64.tar.gz
install -m 755 crictl /usr/local/bin/crictl
```

> 使用`crictl`测试一下，确保可以打印出版本信息并且没有错误信息输出

```shell
crictl --runtime-endpoint=unix:///run/containerd/containerd.sock  version
```

### 9.使用`kubeadm`部署`Kubernetes`

> `openEuler`和`Rocky Linux`系统中执行以下的命令

### 在各节点安装`kubeadm`和`kubelet`

```shell
cat << EOF | sudo tee /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://pkgs.k8s.io/core:/stable:/v1.29/rpm/
enabled=1
gpgcheck=1
gpgkey=https://pkgs.k8s.io/core:/stable:/v1.29/rpm/repodata/repomd.xml.key
exclude=kubelet kubeadm kubectl cri-tools kubernetes-cni
EOF
```

```shell
yum makecache
yum install -y kubelet kubeadm kubectl --disableexcludes=kubernetes
```

### 各节点开机启动`kubelet`服务

```shell
systemctl enable kubelet.service
```

##  9.`kubeadm init`

> 使用`kubeadm config print init-defaults` 可以打印集群初始化默认的使用的配置

### 创建初始化配置文件

```yaml
cat << EOF | sudo tee kubeadm-config.yaml
apiVersion: kubeadm.k8s.io/v1beta3
bootstrapTokens:
- groups:
  - system:bootstrappers:kubeadm:default-node-token
  token: abcdef.0123456789abcdef
  ttl: 24h0m0s
  usages:
  - signing
  - authentication
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: 192.168.110.10
  bindPort: 6443
nodeRegistration:
  criSocket: unix:///var/run/containerd/containerd.sock
  imagePullPolicy: IfNotPresent
  taints:
  - effect: NoSchedule
    key: node-role.kubernetes.io/master
---
apiServer:
  certSANs:
  - master-01
  - master-02
  - master-03
  - 192.168.110.10
  - 192.168.110.11
  - 192.168.110.12
  - 192.168.110.254
  extraArgs:
    authorization-mode: Node,RBAC
  timeoutForControlPlane: 4m0s
apiVersion: kubeadm.k8s.io/v1beta3
certificatesDir: /etc/kubernetes/pki
clusterName: kubernetes
controlPlaneEndpoint: 192.168.110.254:8443
controllerManager: {}
dns: {}
etcd:
  external:
    endpoints:
    - https://192.168.110.10:2379
    - https://192.168.110.11:2379
    - https://192.168.110.12:2379
    caFile: /etc/etcd/ssl/ca.pem
    certFile: /etc/etcd/ssl/server.pem
    keyFile: /etc/etcd/ssl/server-key.pem
imageRepository: registry.aliyuncs.com/google_containers
kind: ClusterConfiguration
kubernetesVersion: 1.29.0
networking:
  dnsDomain: cluster.local
  serviceSubnet: 10.96.0.0/12
  podSubnet: 10.244.0.0/16
scheduler: {}
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
cgroupDriver: systemd
EOF
```

### 预先拉取`Kubernetes`需要的基础镜像

```shell
kubeadm config images list --config kubeadm-config.yaml
kubeadm config images pull
```

### 使用`kubeadm`初始化`Kubernetes`集群

```shell
kubeadm init --config kubeadm-init.log-config.yaml >> kubeadm-init.log
```

```shell
Your Kubernetes control-plane has initialized successfully!

To start using your cluster, you need to run the following as a regular user:

  mkdir -p $HOME/.kube
  sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
  sudo chown $(id -u):$(id -g) $HOME/.kube/config

Alternatively, if you are the root user, you can run:

  export KUBECONFIG=/etc/kubernetes/admin.conf

You should now deploy a pod network to the cluster.
Run "kubectl apply -f [podnetwork].yaml" with one of the options listed at:
  https://kubernetes.io/docs/concepts/cluster-administration/addons/

You can now join any number of control-plane nodes by copying certificate authorities
and service account keys on each node and then running the following as root:

  kubeadm join 192.168.110.254:8443 --token abcdef.0123456789abcdef \
        --discovery-token-ca-cert-hash sha256:62ea33761f845c9a810ac0ed596dcc61af23e9807ea8a34f7274c47f9682b8fb \
        --control-plane 

Then you can join any number of worker nodes by running the following on each as root:

kubeadm join 192.168.110.254:8443 --token abcdef.0123456789abcdef \
        --discovery-token-ca-cert-hash sha256:62ea33761f845c9a810ac0ed596dcc61af23e9807ea8a34f7274c47f9682b8fb
```

## 10.部署`Calico`网络组建

[https://docs.tigera.io/calico/latest/getting-started/kubernetes/self-managed-onprem/onpremises](https://docs.tigera.io/calico/latest/getting-started/kubernetes/self-managed-onprem/onpremises)

如果使用的是 `Pod cidr` ，请跳至下一步。 如果在 `kubeadm` 中使用不同的 `Pod CIDR`，则无需更改 `Calico` 将根据运行配置自动检测 `CIDR`。 对于其他平台，请确保在清单中取消注释 `CALICO_IPV4POOL_CIDR` 变量，并将其设置为与您选择的 `Pod CIDR` 相同的值。`192.168.0.0/16`

![image-20240902144503174](https://raw.githubusercontent.com/it-haozai/Pictures/main/img/image-20240902144503174.png)
