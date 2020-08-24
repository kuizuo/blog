# Python

默认指定utf8编码 如果要为源文件指定字符编码 则在（首行）后插入至少一行特殊的注释行来定义源文件的编码: 格式如下

``` python
  # -*- coding: encoding -*-
  encoding为编码格式 如utf-8
  code...
```

* 使用 4 空格缩进，而非 TAB
* 折行以确保其不会超过 79 个字符
* 推荐类名用 `驼峰命名` ， 函数和方法名用 `小写_和_下划线` 。总是用 self 作为方法的第一个参数

### 算术运算

除法( `/` )永远返回一个浮点数。如要使用 floor 除法 并且得到整数结果（丢掉任何小数部分），你可以使用 `//` 运算符；要计算余数你可以使用 `%` ，用 `**` 运算符可以计算幂乘方

### 字符串

如果你前面带有 \ 的字符被当作特殊字符，你可以使用*原始字符串*，方法是在第一个引号前面加上一个 `r` :

``` python
>>> print('C:\some\name')
C:\some
ame
>>> print(r'C:\some\name') 
C:\some\name
```

三引号"""  类似于js的反引号``

字符串可以由 + 操作符连接(粘到一起)，可以由 * 表示重复: 如

``` python
3 * 'un' + 'ium'
'unununium'
```

相邻的两个字符串文本自动连接在一起。只用于两个字符串文本，不能用于字符串表达式:

``` python
'Py' 'thon'
'Python'
```

字符串相当于数组可以有索引值(从0开始)取值, 也可为负数 从右边开始取: 如

```python 
  word = 'Python'
  word[0] 'P'
  word[-1] 'n' 

``` 
除了索引，还支持 切片。索引用于获得单个字符，切片 让你获得一个子字符串:

```python 
>>> word[0:2]
'Py'
>>> word[2:5]
'tho'
```

==注意，包含起始的字符，不包含末尾的字符。这使得 s[:i] + s[i:] 永远等于 s:==

一个过大的索引值(即下标值大于字符串实际长度)将被字符串实际长度所代替，当上边界比下边界大时(即切片左值大于右值)就返回空字符串:

```python 
word[4:42]
'on'
word[42:]
''

``` 
同其他语言 字符串不可被更改 

置函数 len() 返回字符串长度:

### 列表

类比于js的数组

所有的切片操作都会返回一个包含请求的元素的新列表。这意味着下面的切片操作返回列表一个新的（浅）拷贝副本:
```python
>>> squares[:]
[1, 4, 9, 16, 25]
```

同时也支持拼接 arr1 + arr2

##### 列表list的一些方法 (基本和数组差不多)

* `append()`
方法在后面添加元素  相当于 `a[len(a):] = [x]。`
* `list.extend(L)`
将一个给定列表中的所有元素都添加到另一个列表中，相当于 `a[len(a):] = L。`
* `insert(index, w)`
指定索引前添加元素w 而 `a.insert(len(a), x)` 相当于 `a.append(x)` 。

* `list.index(x)`
返回列表中第一个值为 x 的元素的索引。如果没有匹配的元素就会返回一个错误。

* `list.count(x)`
返回 x 在列表中出现的次数。

* `list.clear()`
从列表中删除所有元素。相当于 `del a[:]` 也可 `arr[:] = []` 清空列表 `[:]` 可省略

* `list.copy()`
返回列表的一个浅拷贝。等同于 `a[:` ]`。

##### 列表推导式

例如, 假设我们创建一个 squares 列表, 可以像下面方式:
```python 
squares = []
for x in range(10):

    squares.append(x**2)

squares 

# [0, 1, 4, 9, 16, 25, 36, 49, 64, 81]

``` 
注意这个 for 循环中的被创建(或被重写)的名为 x 的变量在循环完毕后依然存在。使用如下方法，我们可以计算squares的值而不会产生任何的副作用:

 `squares = list(map(lambda x: x**2, range(10)))`
或者，等价于:
 `squares = [x**2 for x in range(10)]`
再例如，如下的列表推导式结合两个列表的元素，如果元素之间不相等的话:

```python
[(x, y) for x in [1,2,3] for y in [3,1,4] if x != y]
[(1, 3), (1, 4), (2, 3), (2, 1), (2, 4), (3, 1), (3, 4)]
```

等同于:

``` python
combs = []
for x in [1, 2, 3]:
   for y in [3, 1, 4]:
       if x != y:
           combs.append((x, y))
```

一些例子:

``` python
>>> vec = [-4, -2, 0, 2, 4]
>>> # create a new list with the values doubled
>>> [x*2 for x in vec]
[-8, -4, 0, 4, 8]
>>> # filter the list to exclude negative numbers
>>> [x for x in vec if x >= 0]
[0, 2, 4]
>>> # apply a function to all the elements
>>> [abs(x) for x in vec]
[4, 2, 0, 2, 4]
>>> # call a method on each element
>>> freshfruit = ['  banana', '  loganberry ', 'passion fruit  ']
>>> [weapon.strip() for weapon in freshfruit]
['banana', 'loganberry', 'passion fruit']
>>> # create a list of 2-tuples like (number, square)
>>> [(x, x**2) for x in range(6)]
[(0, 0), (1, 1), (2, 4), (3, 9), (4, 16), (5, 25)]
>>> # the tuple must be parenthesized, otherwise an error is raised
>>> [x, x**2 for x in range(6)]
  File "<stdin>", line 1, in ?
    [x, x**2 for x in range(6)]
               ^
SyntaxError: invalid syntax
>>> # flatten a list using a listcomp with two 'for'
>>> vec = [[1,2,3], [4,5,6], [7,8,9]]
>>> [num for elem in vec for num in elem]
[1, 2, 3, 4, 5, 6, 7, 8, 9]
```

##### 嵌套的列表推导式

考虑下面由三个长度为 4 的列表组成的 3x4 矩阵:
```python 

>>> matrix = [

...     [1, 2, 3, 4], 
...     [5, 6, 7, 8], 
...     [9, 10, 11, 12], 
... ]

``` 
交换行和列，可以用嵌套的列表推导式:
```python 
>>> [[row[i] for row in matrix] for i in range(4)]
[[1, 5, 9], [2, 6, 10], [3, 7, 11], [4, 8, 12]]
```

像前面看到的，嵌套的列表推导式是对 for 后面的内容进行求值，所以上例就等价于:
```python 

>>> transposed = []
>>> for i in range(4):

   transposed.append([row[i] for row in matrix])

>>> transposed

[[1, 5, 9], [2, 6, 10], [3, 7, 11], [4, 8, 12]]

``` 
反过来说，如下也是一样的:
```python 
>>> transposed = []
>>> for i in range(4):
...     transposed_row = []
...     for row in matrix:
...         transposed_row.append(row[i])
...     transposed.append(transposed_row)

>>> transposed
[[1, 5, 9], [2, 6, 10], [3, 7, 11], [4, 8, 12]]

```

在实际中，你应该更喜欢使用内置函数组成复杂流程语句。对此种情况 zip() 函数将会做的更好:

`list(zip(*matrix))` 直接交换矩阵的行和列

##### del语句

`del a[索引]` 可以删除指定索引 或者索引的范围

### 元组和序列

一个元组由数个逗号分隔的值组成: 如下

``` python
>>> t = 12345, 54321, 'hello!'
>>> t[0]
12345
>>> t
(12345, 54321, 'hello!')

... u = t, (1, 2, 3, 4, 5)
>>> u
((12345, 54321, 'hello!'), (1, 2, 3, 4, 5))

# Tuples are immutable: 元组里的值是无法改变的
... t[0] = 88888  #报错
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
TypeError: 'tuple' object does not support item assignment

#但是可以包含可变对象
... v = ([1, 2, 3], [3, 2, 1])
>>> v
([1, 2, 3], [3, 2, 1])
```

定义一个空元组 `empty = ()`

### 集合(set)

大括号或 set() 函数可以用来创建集合。注意：想要创建空集合，你必须使用 set() 而不是 {}。后者用于创建空字典

* 集合里不存在有相同的元素, 如果有则合并
* 元素 in 集合 可以判断是否在集合内

集合的交 并 差 对称差集
``` python 

>>> a = set('abracadabra') # a r b c d
>>> b = set('alacazam') # a c l m z
>>> a - b       # 在a 但不在b 的元素

{'r', 'd', 'b'}

>>> a | b       # 在a 或者在b 的元素

{'a', 'c', 'r', 'd', 'b', 'm', 'z', 'l'}

>>> a & b       # 在a 且在b 的元素

{'a', 'c'}

>>> a ^ b       # 在a 或在b 但是不是公同元素

{'r', 'd', 'b', 'm', 'z', 'l'}

``` 

### 字典(dict)

相当于js的对象 
`{'key1':value1, 'key2':value2}` 或者用 `dict()` 构造函数 来创建字典

例子

```python
>>> dict([('sape', 4139), ('guido', 4127), ('jack', 4098)])
{'sape': 4139, 'jack': 4098, 'guido': 4127}
```

关键字都是简单的字符串，有时通过关键字参数指定 key-value 对更为方便:

``` python
>>> dict(sape=4139, guido=4127, jack=4098)
{'sape': 4139, 'jack': 4098, 'guido': 4127}
```

#### 序列

就是列表 如 ['tic', 'tac', 'toe']

#### 字典与序列的循环

`d.keys()` 和 `d.value()` 和 `d.items()`

``` python
for k, v in knights.items():
    print(k, v)
#同js的for of 解构赋值
```

序列可用 `enumerate()` 函数

``` python
>>> for i, v in enumerate(['tic', 'tac', 'toe']):
...     print(i, v)
0 tic
1 tac
2 toe
```

同时循环两个或更多的序列，可以使用 `zip()` 整体打包:

``` python
>>> questions = ['name', 'quest', 'favorite color']
>>> answers = ['lancelot', 'the holy grail', 'blue']
>>> for q, a in zip(questions, answers):
...     print('What is your {0}?  It is {1}.'.format(q, a))

What is your name?  It is lancelot.
What is your quest?  It is the holy grail.
What is your favorite color?  It is blue.
```

逆向循环序列的话，调用 `reversed()` 函数
顺序循环序列的话，使用 `sorted()` 函数，它不改动原序列，而是生成一个新的已排序的序列

### 流程控制

#### if语句

js 中的的 `else if` 相当于python的 `elif` 如

``` python
if x < 0:
  print('x小于0')
elif x == 0:
  print('x等于0')
else :
  print('x大于0')
```

其中条件语句中的括号是可以*省略*的(也推荐省略)

#### for语句

一般用法
 `for i in arr:`
类似于js的for of 直接是元素 不是索引

如果是要计次循环首的 则用 `range()`
```python 
for i in range(5):

    print(i)

``` 
其中 range可有三个参数

* 参数1: 开始值(默认为0)
* 参数2: 结束值(只有一个参数就是参数2的值)
* 参数3: 递增值(默认为1)

#### 循环中的else 

循环可以有一个 else 子句；它在循环迭代完整个列表（对于 for ）或执行条件为 false （对于 while ）时执行，但循环被 `break` 中止的情况下==不会执行==。

用法: 在for 或者while 同一列加上else即可

#### pass 语句

pass 语句什么也不做。它用于那些语法上必须要有什么语句，但程序什么也不做的场合，例如:

```python
while True:
    pass 
```

用于创建最小结构的类:

``` python
class MyEmptyClass:
    pass
```

#### 函数 def

 `def 函数名([参数]):`
1. 设置默认参数值

  直接在参数后加上=值 即可
  然后有默认参数值相当于可选参数
  如果没有默认参数值 就必须要传入参数 和js有所不同
例子:

``` python
i = 5
def f(arg=i):
    print(arg)
i = 6
f()
# 将会输出 5。 优先默认值
```

``` python
def f(a, L=[]):
    L.append(a)
    return L

print(f(1)) # [1]
print(f(2)) # [1, 2]
print(f(3)) # [1, 2, 3]
# 函数在后续调用过程中会累积（前面）传给它的参数
```

2. 关键字参数

`func(keyword = value)` 允许这样的调用 (keyword要与参数名同名)

如

``` python
def func(a,b=12):
  print(a+b)

func(a = 12,b=34) #46

```

3. 可变参数列表

参数名为 `*args` 这样 如

```python 
def concat(*args, sep="/"):

    return sep.join(args)

concat("earth", "mars", "venus")# 'earth/mars/venus'

``` 
4. 参数列表的分拆

对于传入的参数 如果为列表 可以加*转化为对于的参数 用逗号隔开那种 如
```python 
args = [3, 6]
list(range(*args))            
[3, 4, 5]
```

如果为字典的话 则可以加**

5. Lambda 形式

先不写 没看明白 

6. 文档字符串

`函数名.__doc` 即可获取文档第一行的字符串
第一行应该是关于对象用途的简介。简短起见，不用明确的陈述对象名或类型，因为它们可以从别的途径了解到（除非这个名字碰巧就是描述这个函数操作的动词）。这一行应该以大写字母开头，以句号结尾。

看例子
```python 
def my_function():

    """
    这是文档字符串
    """
    pass

print(my_function.__doc__) #这是文档字符串

``` 
7. 函数注解

例子:

```python 
def f(ham: 42, eggs: int = 'spam') -> "Nothing to see here":
   print("Annotations:", f.__annotations__)
   print("Arguments:", ham, eggs)

f('wonderful')
# Annotations: {'ham': 42, 'eggs': <class 'int'>, 'return': 'Nothing to see here'}
# Arguments: wonderful spam
```

### 模块

导入的模块可以通过 `模块.__name` 来获取模块名

* 导入方式 `import 模块`
* `from 模块 import 模块方法` (用*可以导入所有除了以下划线( _ )开头的命名。)

#### 作为脚本来执行模块

在模块后加入如下代码:

```python 
if __name__ == "__main__":

    import sys
    func(int(sys.argv[1]))

``` 
然后命令行执行下面代码
 `python module.py <arguments>`
这时候模块就会执行func函数的代码 

#### 模块的搜索路径

#### dir() 函数

内置函数 `dir()` 用于按模块名搜索模块定义，它返回一个字符串类型的存储列表
无参数调用时， `dir()` 函数返回当前定义的命名:

注意该列表列出了所有类型的名称：变量，模块，函数，等等。

`dir()` 不会列出内置函数和变量名。如果你想列出这些内容，它们在标准模块 `builtins` 中定义

### 输入和输出

将任意值转为字符串的方法: `repr()` 或 `str()` 函数。  两个效果如下  区别在于读不读取引号

注意: ==#print输出时会去掉引号==
```python
>>> s = 'Hello, world.'
>>> str(s)
Hello, world.
>>> repr(s)
'Hello, world.'

# 字符串再转字符串
>>> repr('abd')  #repr转换后是在'abd'的外层又加了一层引号
"'abd'"
>>> str('abd')   #str转换后还是原来的值
'abd'
>>> str('abd') == 'abd'
True
>>> repr('abd') == 'abd'
False
>>> len(repr('abd'))  #repr转换后的字符串和str转换后的字符串个数都是不一样的
5
>>> len(str('abd'))
3
```

##### repr的使用场景

这一特性(在外面套一层引号)在拼接完字符串用eval执行时是特别有用的，如果不用repr而是采用str会报错，举例，将字符串s = 'abdcf'转换成列表，如果用eval自己实现的话可以这样写：

``` python
>>> s = 'abdcf'
>>> eval('['+','.join([repr(i) for i in s])+']')
['a', 'b', 'd', 'c', 'f']
>>> eval('['+','.join([str(i) for i in s])+']')    #str报错
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "<string>", line 1, in <module>
NameError: name 'b' is not defined
```

为什么会报错呢？当', '.join([str(i) for i in s])拼接后的结果'a, b, d, c, f'只有一层引号，eval执行时会去掉这层引号，就成了a, b, d, c, f，解释器就会当做变量对待，但是并没有定义这样的变量，所以报NameError错误

``` python
>>> ','.join([repr(i) for i in s])
"'a','b','d','c','f'"
>>> ','.join([str(i) for i in s])
'a,b,d,c,f'
```

##### str和repr总结

1. 除了字符串类型外，使用str还是repr转换没有什么区别，字符串类型的话，外层会多一对引号，这一特性有时候在eval操作时特别有用；
2. 命令行下直接输出对象调用的是对象的repr方法，print输出调用的是str方法

#### str的一些方法

* `str.rjust()`
字符串输出到一列，并通过向左侧填充空格来使其右对齐  类似的还有 `str.ljust()` 向右侧 | `str.center()` 居中

* `str.zfill()`
用于向数值的字符串表达左侧填充 0。该函数可以正确理解正负号:

* `str.format()` 的基本用法如下:

``` python
>>> print('We are the {} who say "{}!"'.format('knights', 'Ni'))
#We are the knights who say "Ni!"

# 指明数字的话 
>>> print('{0} and {1}'.format('spam', 'eggs'))
spam and eggs
>>> print('{1} and {0}'.format('spam', 'eggs'))
eggs and spam

#位置参数和关键字参数可以随意组合:
>>> print('The story of {0}, {1}, and {other}.'.format('Bill', 'Manfred', other='Georg'))
#The story of Bill, Manfred, and Georg.
```

`'!a'` (应用 ascii())， `'!s'` （应用 str() ）和 `'!r'` （应用 repr() ）可以在格式化之前转换值:

字段名后允许可选的 ':' 和格式指令。这允许对值的格式化加以更深入的控制。下例将 Pi 转为三位精度。

``` python
>>> print('The value of PI is approximately {0:.3f}.'.format(math.pi))
The value of PI is approximately 3.142.
```

在字段后的 ':' 后面加一个整数会限定该字段的最小宽度，这在美化表格时很有用:

``` python
>>> table = {'Sjoerd': 4127, 'Jack': 4098, 'Dcab': 7678}
>>> for name, phone in table.items():
...     print('{0:10} ==> {1:10d}'.format(name, phone))

Jack       ==>       4098
Dcab       ==>       7678
Sjoerd     ==>       4127

```

如果你有个实在是很长的格式化字符串，不想分割它。如果你可以用命名来引用被格式化的变量而不是位置就好了。有个简单的方法，可以传入一个字典，用中括号( '[]' )访问它的键:

``` python
>>> table = {'Sjoerd': 4127, 'Jack': 4098, 'Dcab': 8637678}
>>> print('Jack: {0[Jack]:d}; Sjoerd: {0[Sjoerd]:d}; '
          'Dcab: {0[Dcab]:d}'.format(table))
Jack: 4098; Sjoerd: 4127; Dcab: 8637678
```

也可以用 ‘**’ 标志将这个字典以关键字参数的方式传入:

``` python
>>> table = {'Sjoerd': 4127, 'Jack': 4098, 'Dcab': 8637678}
>>> print('Jack: {Jack:d}; Sjoerd: {Sjoerd:d}; Dcab: {Dcab:d}'.format(**table))
Jack: 4098; Sjoerd: 4127; Dcab: 8637678
```

#### 文件读写

用 `open(filename, mode)` 打开文件对象  mode 参数是可选的，默认为 `'r'`
要读取文件内容，需要调用 `f.read(size)` ，该方法读取若干数量的数据并以字符串形式返回其内容， `size` 是可选的数值，指定字符串长度。如果没有指定 `size` 或者指定为负数，就会读取并返回整个文件。当文件大小为当前机器内存两倍时，就会产生问题。反之，会尽可能按比较大的 `size` 读取和返回数据。如果到了文件末尾， `f.read()` 会返回一个空字符串（''）:

你可以循环遍历文件对象来读取文件中的每一行。这是一种内存高效、快速，并且代码简介的方式:

``` python
>>> for line in f:
...     print(line, end='')
...
This is the first line of the file.
Second line of the file
```

如果你想把文件中的所有行读到一个列表中，你也可以使用 `list(f)` 或者 `f.readlines()` 。

`f.write(string)` 方法将 string 的内容写入文件，并返回写入字符的长度 想要写入其他非字符串内容，首先要将它转换为字符串

当你使用完一个文件时，调用 `f.close()` 方法就可以关闭它并释放其占用的所有系统资源。 在调用 `f.close()` 方法后，试图再次使用文件对象将会自动失败。

用关键字 with 处理文件对象是个好习惯。它的先进之处在于文件用完后会自动关闭，就算发生异常也没关系。它是 try-finally 块的简写:

``` python
>>> with open('workfile', 'r') as f:
...     read_data = f.read()
>>> f.closed
True
```

##### py的json数据

### Python标准库

#### os

`import os` 导入os模块即可 
用 `import os` 风格而非 `from os import *` 。这样可以保证随操作系统不同而有所变化的 `os.open()` 不会覆盖内置函数 `open()` 。

一些方法

* `os.getcwd()` 获取脚本执行路径 

可以通过 `os.path.abspath()` 获得绝对路径
 `print(os.path.abspath(os.path.dirname(__file__)))`
`os.path.dirname(os.getcwd())` 获取上级路径

* `os.chdir('/server/accesslogs')` 设置工作区路径
* `os.system('mkdir today')` 在系统shell中运行命令mkdir

针对日常的文件和目录管理任务，shutil 模块提供了一个易于使用的高级接口:

```python 
import shutil
shutil.copyfile('data.db', 'archive.db')

shutil.move('/build/executables', 'installdir')

``` 

##### 文件通配符

glob 模块提供了一个函数用于从目录通配符搜索中生成文件列表:
```python
>>> import glob
>>> glob.glob('*.py')
['primes.py', 'random.py', 'quote.py']
```

##### 命令行参数

通用工具脚本经常调用命令行参数。这些命令行参数以链表形式存储于 sys 模块的 argv 变量。例如在命令行中执行 python demo.py one two three 后可以得到以下输出结果:

``` python
>>> import sys
>>> print(sys.argv)
['demo.py', 'one', 'two', 'three']
```

##### 日期和时间

datetime 模块为日期和时间处理同时提供了简单和复杂的方法。支持日期和时间算法的同时，实现的重点放在更有效的处理和格式化输出。该模块还支持时区处理。

``` python
>>> # dates are easily constructed and formatted
>>> from datetime import date
>>> now = date.today()
>>> now
datetime.date(2003, 12, 2)
>>> now.strftime("%m-%d-%y. %d %b %Y is a %A on the %d day of %B.")
'12-02-03. 02 Dec 2003 is a Tuesday on the 02 day of December.'

>>> # dates support calendar arithmetic
>>> birthday = date(1964, 7, 31)
>>> age = now - birthday
>>> age.days
14368
```

### 类

``` python
class MyClass:
  """A simple example class"""
    def __init__(self, realpart, imagpart):
      self.r = realpart
      self.i = imagpart # 实例(成员)变量
    
    i = 12345 # 类变量 
    def f(self):
        return 'hello world'

```

实例化类无需用 `new()` 关键词 `x = MyClass()` 即可

其中 `def __init__()` 这个为构造函数  第一个参数 `self` 可以细节为js的this

每个值都是一个对象，因此每个值都有一个 类( class ) （也称为它的 类型( type ) ），它存储为 `object.__class__` 。

#### 私有变量

只能从对像内部访问的“私有”实例变量，在 Python 中不存在。但 Python 有个变通的方法
也就是成员变量前加两个下划线`__`

名称重整是有助于子类重写方法，而不会打破组内的方法调用。例如:
```python
class Mapping:
    def __init__(self, iterable):
        self.items_list = []
        self.__update(iterable)

    def update(self, iterable):
        for item in iterable:
            self.items_list.append(item)

    __update = update   # private copy of original update() method

class MappingSubclass(Mapping):

    def update(self, keys, values):
        # provides new signature for update()
        # but does not break __init__()
        for item in zip(keys, values):
```

#### 继承

定义如下所示:
``` python
class DerivedClassName(BaseClassName):
    ...code
```
命名 `BaseClassName` (示例中的基类名(父类))必须与派生类定义在一个作用域内。除了类，还可以用表达式，基类定义在另一个模块中时这一点非常有用:`class DerivedClassName(modname.BaseClassName):`


#### 多继承

```python
class DerivedClassName(Base1, Base2, Base3):
```
