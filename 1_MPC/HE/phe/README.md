# 代码说明
代码为文章 [《经典同态加密算法Paillier解读 - 原理、实现和应用》](https://blog.csdn.net/gameboxer/article/details/126948240) 的配套代码。包含了原始的paillier算法实现，和后续不同优化的实现。项目文件的内如如下：

- paillier_origin.py是原始的paillier算法的实现代码
- paillier_g.py是对参数g优化后的实现代码
- paillier_exp.py是paillier_g.py优化代码的基础上，对高阶幂运算优化后的代码
- paillier_crt.py是paillier_exp.py优化代码的基础上，使用中国剩余定理对高阶模幂运算优化后的代码

相关原始论文可参考对应文章中的参考文献部分