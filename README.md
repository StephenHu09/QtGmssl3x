# 基于 GmSSL 库的 SM2算法调用Qt实现
GmSSL 版本对应 v3.1.1 ，源码链接： https://github.com/guanzhi/GmSSL

Qt 版本 5.15.2

纯代码依赖实现，使用 VS 编译的 dll库老是有个莫名其妙的崩溃问题，可能与编译环境有关，懒得去分析了。
直接依赖源代码反而更方便多平台的移植，也就多了一点点编译时间。

## 通用性验证
1. 与网站工具 https://the-x.cn/zh-cn/cryptography/Sm2.aspx 进行相互加解密测试OK （Hex密文采用旧格式）

2. 与 Java 库 https://github.com/antherd/sm-crypto 的密文数据可以通用（Hex密文采用旧格式）

## 调试备忘
1. 密钥生成可以使用网站工具 https://const.net.cn/tool/sm2/genkey/

2. 关于密文格式问题 https://github.com/guanzhi/GmSSL/issues/1366  存在 04开头和30开头两种格式，不能混用，有些Java库会默认去掉开头的04。

3. pem 密钥文件生成，可以通过代码接口将Hex密钥保存为pem文件，也可以用 https://the-x.cn/zh-cn/cryptography/Sm2.aspx 网站将 HEX 密钥数据转化成pem格式，再保存为文件即可，不过需要注意私钥pem文件格式的差异，Gmssl库中有两种加载私钥pem的接口。

4. pem私钥的两种格式问题：
sm2_private_key_to_pem 将生成 -----BEGIN EC PRIVATE KEY----- 格式的pem文件，
而 sm2_private_key_info_to_pem 接口生成的是 -----BEGIN PRIVATE KEY----- 格式的pem文件。
相应的，使用不同接口生成的pem，也要使用对应的 from 接口进行解析，不然会不匹配报错。
sm2_private_key_to_pem 对应 sm2_private_key_from_pem；
sm2_private_key_info_to_pem 对应 sm2_private_key_info_from_pem。

5. 关于数据格式问题，Qt中UI显示都是QString 类型的数据，密文实际是Hex的字符串，在QByteArray 数据转换时需要注意，不能直接使用 str.toUtf8(), 应该使用 QByteArray::fromHex(str.toUtf8())

