## Pwn 题环境启动方式

### 本地测试

先利用 chmod 命令赋予文件执行权限，下面是懒人写法

```bash
chmod 777 -R *
```

**本地执行题目文件**

```bash
./res/pwn
```

**脚本执行题目文件**

建议更改文件名为 chall，意为 challange

文件名为 pwn，脚本可能会出错

```python
p = process(['./chall'])
```

---

### 远程测试

先进入目录，然后输入以下命令

```bash
docker-compose up
```

之后题目默认会开在 9999 端口

**本地连接题目文件**

```bash
nc localhost 9999
```

**脚本连接题目文件**

```python
p = remote('pwn.hsctf.com', 5002)
```

