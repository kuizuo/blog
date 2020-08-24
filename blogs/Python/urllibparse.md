#### 一、获取url参数

###### ①解析url（urlparse）



```python
from urllib import parse
url = 'http://ccforever/get_page?page=1&index=1'
b = parse.urlparse(url)
print(b)
结果为：
ParseResult(scheme='http', netloc='ccforever', path='/get_page', params='', query='page=1&index=1', fragment='')
```

###### ②获取query参数（parse_qs）

a.直接获取query
 `print(b.query)`
 结果为：
 `page=1&index=1`
 ==================================================================================
 b.解析query参数
 `c = parse.parse_qs(b.query)`
 `print(c)`
 结果为：
 `{'page': ['1'], 'index': ['1']}`
 ==================================================================================
 **注意**：当query参数中有 *‘ + ’* 的时候，会被解码，并不是我们想要的
 **例：**
 `d = parse.parse_qs('page=7464ssfa18f46+78dasf&index=2')`
 `print(d)`
 结果为：
 `{'page': ['7464ssfa18f46 78dasf'], 'index': ['2']}`

#### 二、编码成url参数（urlencode）



```python
from urllib import parse
url_dict = {
    'name': 'AlanWalker',
    'page': 1,
    'index': 1
}
f = urllib.parse.urlencode(url_dict)
print(f)
结果为：
name=AlanWalker&page=1&index=1
```

**注意：此函数会将空格自动编码成 ‘+’号**



```python
from urllib import parse
url_dict = {
    'name': 'Alan Walker',     此处中间多了空格
    'page': 1,
    'index': 1
}
f = urllib.parse.urlencode(url_dict)
print(f)
结果为：
name=Alan+Walker&page=1&index=1    结果处中间的空格变成了‘+’
```

#### 三、（编码）quote/quote_plus

###### ①quote



```python
from urllib import parse
url = 'http://ccforever/get_page++?*-&%$#@!'
g = parse.quote(url)
print(g)
```

结果为：
 `http%3A//ccforever/get_page%2B%2B%3F%2A-%26%25%24%23%40%21`  编码除斜线 **‘/’**外所有符号

###### ②quote_plus



```python
from urllib import parse
url = 'http://ccforever/get_page++?*-&%$#@!'
g = parse.quote_plus(url)
print(g)
```

结果为：
 `http%3A%2F%2Fccforever%2Fget_page%2B%2B%3F%2A-%26%25%24%23%40%21`  编码包括斜线 **‘/’**的所有符号

#### 四、（解码）unquote/unquote_plus

###### ①unquote



```python
from urllib import parse
url = 'http://ccforever/get_page++?'
g = parse.unquote(url)
print(g)
```

结果为：
 `http://ccforever/get_page++?`  此处未解码 **‘+’**号

###### ②unquote_plus



```python
from urllib import parse
url = 'http://ccforever/get_page++?'
g = parse.unquote_plus(url)
print(g)
```

结果为：
 `http://ccforever/get_page ?`  此处将 **‘+’**号解码为空格



