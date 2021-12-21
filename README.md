# Trivial WAVE (ChainPer)

## 使用的IBE算法

由于pycocks密文长度过长，改使用FIBRE

* 参考https://github.com/jiangtaoluo/IB-PRE

首先要安装charm crypto库

* 直接clone dev分支

    * https://github.com/JHUISI/charm
    
* 安装PBC

    * http://pages.cs.wisc.edu/~ace/install-charm.html
    
* 安装

    * https://jhuisi.github.io/charm/install_source.html


## 区块链运行命令

首先需要安装nodejs，推荐使用nvm安装：

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.38.0/install.sh | bash
source ~/.bashrc
nvm list-remote
nvm install v12.18.1
```

安装truffle

```
npm install -g cnpm --registry=https://registry.npm.taobao.org
cnpm install -g truffle
truffle version
```

运行truffle develop并且编译合约上链
```
cd contracts/storage-box
truffle develop
> migrate --reset
```

把log中的合约地址复制下来，粘贴到transaction.py中

## 客户端相关命令

```bash
python3 main.py -a mke -o Alice
python3 main.py -a grant -i admin -s Alice -p read@air-condition -r 10/9/2021:21/9/2021
python3 main.py -a prove -s Alice -p read@air-condition -t CBackyx
python3 main.py -a verify -s Alice -p read@air-condition
python3 main.py -a revoke -i Alice -s Bob -p read@air-condition -r 10/9/2021:21/9/2021
python3 main.py -a prove -s Jack -p read@air-condition -t CBackyx
```
