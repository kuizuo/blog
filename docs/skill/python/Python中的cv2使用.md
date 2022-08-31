---
id: python-cv2-usage
slug: /python-cv2-usage
title: Python中的cv2使用
date: 2022-03-06
authors: kuizuo
tags: [python]
keywords: [python]
---

<!-- truncate -->

[模块 cv2 的用法 - 陨落&新生 - 博客园 (cnblogs.com)](https://www.cnblogs.com/shizhengwen/p/8719062.html)

[Python-OpenCV 基本操作 cv2 - 菜鸟程序猿\_python - 博客园 (cnblogs.com)](https://www.cnblogs.com/zlel/p/9267629.html)

## 常用方法

### 读取图像

cv2.imread(filepath,flags)

- filepath：要读入图片的完整路径

- flags：读入图片的标志

- - cv2.IMREAD_COLOR：默认参数(3)，读入一副彩色图片，忽略 alpha 通道
  - cv2.IMREAD_GRAYSCALE：读入灰度图片
  - cv2.IMREAD_UNCHANGED：顾名思义，读入完整图片，包括 alpha 通道

### 写入图像

cv2.imwrite(filepath, img, flags)

- filepath: 要保存图像的文件名
- img: 要保存的图像
- flags: 可选的第三个参数，它针对特定的格式：对于 JPEG，其表示的是图像的质量，用 0 - 100 的整数表示，默认 95;对于 png ,第三个参数表示的是压缩级别。默认为 3.

cv2.IMWRITE_JPEG_QUALITY 类型为 long ,必须转换成 int

cv2.IMWRITE_PNG_COMPRESSION, 从 0 到 9 压缩级别越高图像越小。

```python
cv2.imwrite('1.png',img, [int(cv2.IMWRITE_JPEG_QUALITY), 95])
cv2.imwrite('1.png',img, [int(cv2.IMWRITE_PNG_COMPRESSION), 9])
```

### 显示图像

演示代码如下

```python
import cv2

img = cv2.imread('temp.jpg')
cv2.imwrite('save.jpg', img)
cv2.imshow('img', img)
cv2.waitKey(0)
cv2.destroyAllWindow()
```

### img 的一些属性

```python
img.shape # (1200, 1920, 3) 宽、高、通道数
img.size # 像素个数
img.dtype # uint8
```

### 颜色转化

由于 cv2 得到的图片是 BGR 格式，而非传统的 RGB 格式，因此需要进行转化。

有以下三种方法

```python
im_bgr = cv2.imread('temp.jpg')

im_rgb = im_bgr[:, :, [2, 1, 0]]
im_rgb = im_bgr[:, :, ::-1]
im_rgb = cv2.cvtColor(im_bgr, cv2.COLOR_BGR2RGB)
```

还有一些颜色空间转化

```python
#彩色图像转为灰度图像
img2 = cv2.cvtColor(img,cv2.COLOR_RGB2GRAY)
#灰度图像转为彩色图像
img3 = cv2.cvtColor(img,cv2.COLOR_GRAY2RGB)
# cv2.COLOR_X2Y，其中X,Y = RGB, BGR, GRAY, HSV, YCrCb, XYZ, Lab, Luv, HLS
```

### cv 图片对象与二进制图片转化

```python
def bytes2cv(im):
    return cv2.imdecode(np.array(bytearray(im), dtype='uint8'), cv2.IMREAD_UNCHANGED)

def cv2bytes(im):
    return np.array(cv2.imencode('.png', im)[1]).tobytes()
```

### 添加边框

```python
import cv2

poses = [[111, 46, 151, 86], [177, 46, 212, 80],
         [246, 89, 286, 128], [240, 18, 280, 56]]

img = cv2.imread("1.jpg")

for box in poses:
    x1, y1, x2, y2 = box
    img = cv2.rectangle(img, (x1, y1), (x2, y2), color=(0, 0, 255), thickness=2)

cv2.imwrite("result.jpg", img)
```

![result](https://img.kuizuo.cn/result.png)

### 添加文本

```python
import cv2

img = cv2.imread('temp.jpg')
# 图片对象、文本、像素、字体、字体大小、颜色、字体粗细
img_text = cv2.putText(img, "kuizuo", (50, 50),
                    cv2.FONT_HERSHEY_DUPLEX, 5.5, (35, 175, 255), 2)
cv2.imwrite("result.jpg", img_text)
```

效果如下

![image-20220306203918438](https://img.kuizuo.cn/image-20220306203918438.png)

### 图片缩放

```python
import cv2

img = cv2.imread("1.png")
cv2.imshow("img", img)

img1 = cv2.resize(img, (200, 100))

cv2.imshow("img1", img1)

cv2.waitKey()
```
