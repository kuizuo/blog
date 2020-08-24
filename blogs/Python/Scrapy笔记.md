# Scrapy



### 创建项目

在开始爬取之前，您必须创建一个新的Scrapy项目。 进入您打算存储代码的目录中，运行下列命令:

```
scrapy startproject tutorial
```

该命令将会创建包含下列内容的 `tutorial` 目录:

```
tutorial/
    scrapy.cfg
    tutorial/
        __init__.py
        items.py
        pipelines.py
        settings.py
        spiders/
            __init__.py
            ...
```

这些文件分别是:

- `scrapy.cfg`: 项目的配置文件
- `tutorial/`: 该项目的python模块。之后您将在此加入代码。
- `tutorial/items.py`: 项目中的item文件.
- `tutorial/pipelines.py`: 项目中的pipelines文件.
- `tutorial/settings.py`: 项目的设置文件.
- `tutorial/spiders/`: 放置spider代码的目录.

## 定义Item

Item 是保存爬取到的数据的容器；其使用方法和python字典类似， 并且提供了额外保护机制来避免拼写错误导致的未定义字段错误。

类似在ORM中做的一样，您可以通过创建一个 [`scrapy.Item`](https://scrapy-chs.readthedocs.io/zh_CN/0.24/topics/items.html#scrapy.item.Item) 类， 并且定义类型为 [`scrapy.Field`](https://scrapy-chs.readthedocs.io/zh_CN/0.24/topics/items.html#scrapy.item.Field) 的类属性来定义一个Item。 (如果不了解ORM, 不用担心，您会发现这个步骤非常简单)

首先根据需要从dmoz.org获取到的数据对item进行建模。 我们需要从dmoz中获取名字，url，以及网站的描述。 对此，在item中定义相应的字段。编辑 `tutorial` 目录中的 `items.py` 文件:







#### 爬虫步骤：

> **1.创建一个scrapy项目**
>
> ```bash
> scrapy startproject mySpider   #mySpider是项目名字
> ```
>
> **2.生成一个爬虫**
>
> ```css
> scrapy genspider itcast itcast.cn  #itcast是爬虫名字,"itcast.cn"限制爬虫地址,防止爬到其他网站
> ```
>
> **3.提取数据**
>
> ```undefined
> 完善spiders,使用xpath等方法
> ```
>
> **3.保存数据**
>
> ```undefined
> pipelines中保存数据
> ```

**启动爬虫**

```bash
scrapy crawl 爬虫名字    #crawl(抓取的意思)
```

**启动爬虫不打印日志**

```undefined
scrapy crawl 爬虫名字 --nolog
```

**run.py启动爬虫**

```swift
from scrapy import cmdline
cmdline.execute("scrapy crawl lagou".split())
```

![img](https:////upload-images.jianshu.io/upload_images/11614481-663db2329f5633a4.png?imageMogr2/auto-orient/strip|imageView2/2/w/827/format/webp)

Scrapy运行流程

#### spider内容

```python
# -*- coding: utf-8 -*-
import scrapy
#导入items
from tencent.items import TencentItem

#自定义spider类,继承自scrapy.Spider
class ItcastSpider(scrapy.Spider):
    name = 'itcast' #爬虫名字<爬虫启动时候使用:scrapy crawl itcast>
    #允许爬取的范围,防止爬虫爬到了别的网站
    allowed_domains = ['tencent.com']
    #开始爬取的地址,下载中间件提取网页数据
    start_urls = ['https://hr.tencent.com/position.php']
    #数据提取方法,接收下载中间件传过来的response(响应)
    def parse(self, response):
        #处理start_url地址对应的响应
        #提取数据
        # reti = response.xpath("//div[@class='tea_con']//h3/text()").extract()
        # print(reti)

        #分组,[1:-1]切片,不要第一条数据
        li_list = response.xpath('//table[@class="tablelist"]/tr')[1:-1]
        for li in li_list:
            #在item中定义要爬取的字段,以字典形式传入
            item = TencentItem()
            item["name"] = li.xpath(".//h3/text()").extract_first()
            item["title"] = li.xpath(".//h4/text()").extract_first()
            #yield可以返回request对象，BaseItem(items.py中的类),dict,None
            yield item  #yield传到pipeline
        #找到下一页url地址
        next_url = response.xpath('//a[@id="next"]/@href').extract_first()
        #如果url地址的href="地址"不等于javascript:;
        if next_url != "javascript:;":
            next_url = "https://hr.tencent.com/"+ next_url
            #把next_url的地址通过回调函数callback交给parse方法处理
            yield scrapy.Request(next_url,callback=self.parse)
```

> **提取数据**
>  response.xpath('//a[@id="next"]/@href')
>
> body = response.text.replace('\n', '').replace('\r', '').replace('\t', '')
>  re.findall('<a title=".*?" href="(.*?)"', body)

> **从选择器中提取字符串：**
>
> - extract() 返回一个包含有字符串数据的列表
> - extract_first()返回列表中的第一个字符串
>
> **注意:**
>
> - spider中的parse方法名不能修改
> - 需要爬取的url地址必须要属于allow_domain(允许_域)下的连接
> - respone.xpath()返回的是一个含有selector对象的列表

> **为什么要使用yield?**
>  让整个函数变成一个生成器,变成generator(生成器)有什么好处?
>  每次遍历的时候挨个读到内存中,不会导致内存的占用量瞬间变>高python3中range和python2中的xrange同理

> **scrapy.Request常用参数为**
>  callback = xxx：指定传入的url交给那个解析函数去处理
>  meta={"xxx":"xxx"}:实现在不同的解析函数中传递数据,配合callback用
>  dont_filter=False:让scrapy的去重不会过滤当前url，默认开启url去重
>  headers：请求头
>  cookies:cookies,不能放在headers中,独立写出来
>  method = "GET":请求方式,(GET和POST)

#### 爬取详细页和翻页



```python
# -*- coding: utf-8 -*-
import scrapy
from yangguang.items import YangguangItem

class YgSpider(scrapy.Spider):
    name = 'yg'
    allowed_domains = ['sun0769.com']
    start_urls = ['http://wz.sun0769.com/index.php/question/questionType?type=4&page=0']

    def parse(self, response):
        tr_list = response.xpath("//div[@class='greyframe']/table[2]/tr/td/table/tr")
        for tr in tr_list:
            item = YangguangItem()
            item["title"] = tr.xpath("./td[2]/a[@class='news14']/@title").extract_first()
            item["href"] = tr.xpath("./td[2]/a[@class='news14']/@href").extract_first()
            item["publish_date"] = tr.xpath("./td[last()]/text()").extract_first()
            #执行进入url地址,再把item传到下面parse_detail,提取详细页的内容
            yield scrapy.Request(item["href"],callback=self.parse_detail,meta={"item":item})
        #翻页
        #获取url地址
        next_url = response.xpath("//a[text()='>']/@href").extract_first()
        #如果下一页url地址不为空,进入下一页连接
        if next_url is not None:
            yield scrapy.Request(next_url,callback=self.parse)

    #处理详情页
    def parse_detail(self,response):
        #item接收meta传过来的item，在item字典里继续为item添加内容
        item = response.meta["item"]
        #拿到详细页的内容
        item["content"] = response.xpath("//div[@class='c1 text14_2']//text()").extract()
        #拿到详细页的图片地址
        item["content_img"] = response.xpath("//div[@class='c1 text14_2']//img/@src").extract()
        #给图片前面加上http://wz.sun0769.com
        item["content_img"] = ["http://wz.sun0769.com" + i for i in item["content_img"]]
        #把item传给pipeline
        yield item
```

#### items(存储爬取字段)

```python
import scrapy
#scrapy.Item是一个字典
class TencentItem(scrapy.Item):
#scrapy.Field()是一个字典
url = scrapy.Field()
name = scrapy.Field()
```

### 使用pipeline(管道)

```python
from demo1 import settings
import pymongo

class Demo1Pipeline(object):
    def __init__(self):
        #连接mongodb数据库(数据库地址，端口号，数据库)
        client = pymongo.MongoClient(host=settings.MONGODB_HOST, port=settings.MONGODB_PORT)
        #选择数据库和集合
        self.db = client[settings.MONGODB_DBNAME][settings.MONGODB_DOCNAME]
    def process_item(self, item, spider):
        data = dict(item)
        self.db.insert(data)

#完成pipeline代码后,需要在setting中设置开启
ITEM_PIPELINES = {
  #开启管道，可以设置多个管道，'管道地址数值':越小越先执行
  'mySpider.pipelines.MyspiderPipeline': 300,
}
# MONGODB 主机环回地址127.0.0.1
MONGODB_HOST = '127.0.0.1'
# 端口号，默认是27017
MONGODB_PORT = 27017
# 设置数据库名称
MONGODB_DBNAME = 'DouBan'
# 存放本次数据的表名称
MONGODB_DOCNAME = 'DouBanMovies'
```

**第二种：**

```python
class MyspiderPipeline(object):
def __init__(self):
    #连接mongodb数据库(数据库地址，端口号，数据库)
    client = pymongo.MongoClient(host=settings.MONGODB_HOST, port=settings.MONGODB_PORT)
    #选择数据库和集合
    self.db = client[settings.MONGODB_DBNAME]

    #实现存储方法,item是spider传过来的,spider就是自己写的爬虫
    def process_item(self, item, spider):
      table = ''
      #通过spider参数，可以针对不同的Spider进行处理
      #spider.name爬虫的名字
      if spider.name == "itcast":
        #如果爬虫的名字为itcast执行这里面的东西
        table = self.db.表名
        #如果爬虫的名字为itcast2执行这里面的东西
      elif spider.name == "itcast2":
        table = self.db.表名
      table.insert(dict(item))

      #也可以通过item参数，可以针对不同的Item进行处理
      table = ''
      if isinstance(item, 爬虫名字):
        table = self.db.表名
      table.insert(dict(item))
```

## mysql存储

```python
from pymysql import connect
import pymysql
class TxPipeline(object):
    def __init__(self):
        self.conn=connect(host='localhost',port=3306,db='txzp',user='root',passwd='root',charset='utf8')
        self.cc = self.conn.cursor()
    def process_item(self, item, spider):
        print(item["title"],item["href"],item["number"],item["time"],item["duty"])
        aa = (item["title"],item["href"],item["number"],item["time"],item["duty"],item["requirement"])
        sql = '''insert into tx values (0,"%s","%s","%s","%s","%s","%s")'''
        self.cc.execute(sql%aa)
        self.conn.commit()#提交
        # self.cc.close()   #关闭游标会报错
```

> **注意**
>
> - pipeline中process_item方法名不能修改，修改会报错
> - pipeline(管道)可以有多个
> - 设置了pipelines必须开启管道,权重越小优先级越高

> 为什么需要多个pipeline:
>
> - 可能会有多个spider,不同的pipeline处理不同的item的内容
> - 一个spider的内容可能要做不同的操作,比如存入不同的数据库中

#### 简单设置LOG(日志)

> 为了让我们自己希望输出到终端的内容能容易看一些:
>  我们可以在setting中设置log级别
>  在setting中添加一行(全部大写):

```bash
LOG LEVEL="WARNING"
```

默认终端显示的是debug级别的log信息

#### logging模块的使用

**scrapy中使用logging**



```python
#settings中设置
LOG_LEVEL=“WARNING”
LOG_FILE="./a.log"  #设置日志保存的位置，设置会后终端不会显示日志内容
```



```python
#打印logging日志
import logging
#实例化logging，显示运行文件的名字，不写不会显示运行文件的目录
logging = logging.getLogger(__name__)
#日志输出打印
logging.warning(item)

#打印内容(日志创建时间，运行文件的目录，日志级别，打印的内容)
2018-10-31 15:25:57 [mySpider.pipelines] WARNING: {'name': '胡老师', 'title': '高级讲师'}
```

**普通项目中使用logging**
 具体参数信息：https://www.cnblogs.com/bjdxy/archive/2013/04/12/3016820.html



```python
#a.py文件

import logging
#level: 设置日志级别，默认为logging.WARNING
logging.basicConfig(level=logging.INFO,
                    format=
                        #日志的时间
                        '%(asctime)s'
                        #日志级别名称 : 当前行号
                        ' %(levelname)s [%(filename)s : %(lineno)d ]'
                        #日志信息
                        ' : %(message)s'
                        #指定时间格式
                        , datefmt='[%Y/%m/%d %H:%M:%S]')
#实例化logging，显示当前运行文件的名字，不写不会显示运行文件的目录
logging=logging.getLogger(__name__)

if __name__ == '__main__':
    #日志级别打印信息
    logging.info("this is a info log")
```

b.py文件使用a.py文件的logging(日志)



```python
#b.py文件

from a import logging #导入a.py中的实例logging

if __name__ == '__main__':
#warning级别大于info也可以打印,debug级别小于info,不可以打印
logger.warning("this is log b")
```

> **日志级别:**
>
> - debug　　　#调试
> - info　　　 　#正常信息
> - warning　　#警告
> - error　　　#错误
>
> 如果设置日志级别为info，warning级别比info大，warning也可以打印，debug比info小不可以打印
>  如果设置日志级别为warning，info和debug都比warning小，不可以打印

#### 把数据保存到mongodb中

```python
#导入mongodb的包
from pymongo import MongoClient
#实例化client,建立连接
client = MongoClient(host='127.0.0.1',port = 27017)
#选择数据库和集合
collection = client["tencent"]["hr"]

class TencentPipeline(object):
    def process_item(self, item, spider):
        #传过来的数据是对象，把item转化为字典
        item = dict(item)
        #把数据存入mongodb数据库
        collection.insert(item)
        print(item)
        return item
```

#### scrapy shell

> Scrapy shell是一个交互终端，我们可以在未启动spider的情况下尝试及调试代码，也可以用来测试XPath表达式

**使用方法：**



```cpp
命令行输入：
    scrapy shell http://www.itcast.cn/channel/teacher.shtml
```

**常用参数：**



```python
response.url：当前响应的url地址
response.request.url：当前响应对应的请求的url地址
response.headers：响应头
response.body：响应体，也就是html代码，默认是byte类型
response.body.decode()：变为字符串类型
response.request.headers：当前响应的请求头
response.xpath("//h3/text()").extract()：调试xpath，查看xpath可不可以取出数据
```

#### setting设置文件

> 为什么需要配置文件：
>
> - 配置文件存放一些公共的变量(比如数据库的地址,账号密码等)
> - 方便自己和别人修改
> - 一般用全大写字母命名变量名SQL_HOST='192.168.0.1'

参考地址：https://blog.csdn.net/u011781521/article/details/70188171



```python
#常见的设置

#项目名
BOT_NAME = 'yangguang'
#爬虫位置
SPIDER_MODULES = ['yangguang.spiders']
NEWSPIDER_MODULE = 'yangguang.spiders'
#遵守robots协议，robots.txt文件
ROBOTSTXT_OBEY = True
#下载延迟，请求前睡3秒
DOWNLOAD_DELAY = 3
# 默认请求头，不能放浏览器标识
DEFAULT_REQUEST_HEADERS = {
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en',
  "Cookie": "rfnl=https://www.guazi.com/sjz/dazhong/; antipas=2192r893U97623019B485050817",
}
#项目管道，保存数据
ITEM_PIPELINES = {
   'yangguang.pipelines.YangguangPipeline': 300,
}
```

**spiders文件使用settings的配置属性**



```python
#第一种
self.settings["MONGO_HOST"]
#第二种
self.settings.get("MONGO_HOST")
```

**pipelines文件使用settings的配置属性**

```python
spider.settings.get("MONGO_HOST")
```

#### Scrapy中CrawlSpider类

**深度爬虫**

```bash
#创建CrawlSpider爬虫，就多加了-t crawl
scrapy genspider -t crawl cf gov.cn
```

**第一种用法：提取内容页和翻页**

```python
# -*- coding: utf-8 -*-
import scrapy
from scrapy.linkextractors import LinkExtractor
from scrapy.spiders import CrawlSpider, Rule
from tengxun.items import TengxunItem

class TxSpider(CrawlSpider):
    name = 'tx'
    allowed_domains = ['hr.tencent.com']
    #第一次请求的url
    start_urls = ['https://hr.tencent.com/position.php']
    #rules自动提取url地址
    rules = (
        # 内容页,交给parse_item处理数据
        Rule(LinkExtractor(allow=r'position_detail\.php\?id=\d+&keywords=&tid=0&lid=0'), callback='parse_item'),
        # 翻页
        Rule(LinkExtractor(allow=r'position\.php\?&start=\d+#a'), follow=True),
    )
    #处理内容页的数据
    def parse_item(self, response):
        item = TengxunItem()
        #爬取标题
        item["bt"] = response.xpath('//td[@id="sharetitle"]/text()').extract_first()
        #爬取工作要求
        item["gzyq"] = response.xpath('//div[text()="工作要求："]/../ul/li/text()').extract()
        yield item
```

**第二种用法：提取标题页，内容，翻页**

```python
# -*- coding: utf-8 -*-
import scrapy
from scrapy.linkextractors import LinkExtractor
from scrapy.spiders import CrawlSpider, Rule
from tengxun.items import TengxunItem

class Tx2Spider(CrawlSpider):
    name = 'tx2'
    allowed_domains = ['hr.tencent.com']
    start_urls = ['https://hr.tencent.com/position.php']

    rules = (
        #翻页
        Rule(LinkExtractor(allow=r'position\.php\?&start=\d+#a'), callback='parse_item', follow=True),
    )
    #标题页内容
    def parse_item(self, response):
        tr_list = response.xpath('//table[@class="tablelist"]/tr')[1:-1]
        for tr in tr_list:
            item = TengxunItem()
            #爬取标题
            item['bt'] = tr.xpath('./td/a/text()').extract_first()
            #爬取url
            item['url'] = tr.xpath('./td/a/@href').extract_first()
            item['url'] = "https://hr.tencent.com/" + item['url']
            yield scrapy.Request(
                item['url'],
                callback=self.parse_detail,
                meta={"item":item}
            )
    #爬取内容
    def parse_detail(self,response):
        item = response.meta['item']
        item['gzyq'] = response.xpath('//div[text()="工作要求："]/../ul/li/text()').extract()
        yield item
```

```bash
#LinkExtractor 连接提取器,提取url地址
#callback 提取出来的url地址的response会交给callback处理
#follow 当前url地址的响应是否重新进过rules来提取url地址
#提取详细页的url
#CrawlSpider会自动把url补充完整
```

**Rule的匹配细节**

```python
Rule(LinkExtractor(allow=r'position_detail\.php\?id=\d+&keywords=&tid=0&lid=0'), callback='parse_item'),
#这里把该匹配的东西写成正则
#?和.别忘了转义\?  \.
```

```bash
#LinkExtractor 连接提取器,提取url地址
#callback 提取出来的url地址的response会交给callback处理
#follow 当前url地址的响应是否重新进过rules来提取url地址
#提取详细页的url
#CrawlSpider会自动把url补充完整
```

- 用命令创建一个crawlspider的模板:scrapy genspider-t crawl 爬虫名字 域名,也可以手动创建
- CrawiSpider中不能再有以parse为名字的数据提取方法,这个方法被CrawlSpider用来实现基础url提取等功能)
- 一个Rule对象接收很多参数,首先第一个是包含url规则的LinkExtractor对象,常用的还有calback(制定满足规则的url的解析函数的字符串)和follow(response中提取的链接是否需要跟进)
- 不指定callback函数的请求下,如果follow为True,满足该rule的url还会继续被请求
- 如果多个Rule都满足某一个url,会从rules中选择第一个满足的进行操作

**CrawlSpider补充(了解)**

```python
LinkExtractor更多常用链接

LinkExtractor(allow=r'/web/site0/tab5240/info\d+\.htm')

allow:满足括号中"正则表达式"的URL会被提取,如果为空,则全部匹配.
deny:满足括号中"正则表达式"的URL一定不提取(优先级高于allow).
allow_domains:会被提取的链接的domains.
deny_domains:一定不会被提取链接的domains.
restrict_xpaths:使用xpath表达式,和allow共同作用过滤链接,级xpath满足范围内的uri地址会被提取
```

```python
rule常见参数：

Rule(LinkExtractor(allow=r'/web/site0/tab5240/info\d+\.htm'), callback='parse_item', follow=False),

LinkExtractor:是一个Link Extractor对象,用于定义需要提取的链接.
callback:从link_extractor中每获取到链接时,参数所指定的值作为回调函数
follow:是一个布尔(boolean)值,指定了根据该规则从response提取的链接是否需要跟进.如果callback为None,follow 默认设置为True,否则默认为False.
process_links:指定该spider中哪个的函数将会被调用,从link_extractor中获取到链接列表时将会调用该函数,该方法主要用来过滤url.
process_request:指定该spider中哪个的函数将会被调用,该规则提取到每个request时都会调用该函数,用来过滤request
```

# Scrapy分布式爬虫

![img](https:////upload-images.jianshu.io/upload_images/11614481-32e633c81cb88063.png?imageMogr2/auto-orient/strip|imageView2/2/w/613/format/webp)

Scrapy分布式爬虫流程

### Scrapy_redis之domz

domz相比于之前的spider多了持久化和request去重的功能
 domz就是Crawlspider去重和持久化版本
 不能分布式
 可以分布式的是RedisSpider和RedisCrawlspider

Scrapy redis在scrapy的基础上实现了更多,更强大的功能,具体体现在:reqeust去重,爬虫持久化,和轻松实现分布式
 官方站点：https://github.com/rmax/scrapy-redis

```python
#spiders文件夹

爬虫内容和自己写的CrawlSpider没有任何区别
```

```python
settings.py
#写上下面东西Crawlspider就可以去重了
#还可以持久化爬虫，关闭后，在开启继续爬取

DUPEFILTER_CLASS = "scrapy_redis.dupefilter.RFPDupeFilter"  #去重
SCHEDULER = "scrapy_redis.scheduler.Scheduler"  #重写调度器(scheduler)
SCHEDULER_PERSIST = True  #不清楚缓存，队列中的内容是否持久保存(开启后爬虫关闭后,下次开启从关闭的位置继续爬取)

ITEM_PIPELINES = {
    #将数据保存到redis中，屏蔽这条命令
    #'scrapy_redis.pipelines.RedisPipeline': 400,
}

#指定redis地址
REDIS_URL = 'redis://127.0.0.1:6379'
#也可以写成下面形式
#REDIS_HOST = "127.0.0.1"
#REDIS_PORT = 6379
```

**我们执行domz的爬虫，会发现redis中多了一下三个键：**

> - dmoz:requests　　(zset类型)(待爬取)
>    Scheduler队列，存放的待请求的request对象，获取的过程是pop操作，即获取一个会去除一个
> - dmoz:dupefilter　　(set)(已爬取)
>    指纹集合，存放的是已经进入scheduler队列的request对象的指纹，指纹默认由请求方法，url和请求体组成
> - dmoz:items　　(list类型)(item信息)
>    存放的获取到的item信息，在pipeline中开启RedisPipeline才会存入

### Scrapy_redis之RedisSpider

```python
from scrapy_redis.spiders import RedisSpider

#继承RedisSpider
class MySpider(RedisSpider):
#指定爬虫名
name='myspider_redis'

#指定redis中start_urls的键,
#启动的时候只需要往对应的键总存入url地址,不同位置的爬虫就会来获取该url
#所以启动爬虫的命令分类两个步骤:
#(1)scrapy crawl myspider_redis(或者scrapy runspider myspider_redis)让爬虫就绪
#(2)在redis中输入lpush myspider:start_urls"http://dmoztools.net/"让爬虫从这个ur开始爬取
redis_key ='myspider:start_urls'

#手动指定allow_domain,执行爬虫范围
#可以不写
allow_doamin=["dmoztools.net"]

def parse(self, response):
  #普通scrapy框架写法
  ...
```

**启动**

```bash
#爬虫名字
scrapy runspider myspider
或(2选1)
#蜘蛛文件名字
scrapy runspider myspider.py
```

redis运行

```cpp
#redis 添加 键:值 "爬取的网址"
redis-c1i lpush guazi:start_urls "http://ww.guazi.com/sjz/dazhong/"
```

### Scrapy_redis之RedisCrawlSpider

```python
from scrapy.spiders import Rule
from scrapy.linkextractors import LinkExtractor
from scrapy_redis.spiders import RedisCrawlSpider

#继承RedisCrawlSpider
class MyCrawler(RedisCrawlSpider):
#爬虫名字
name='mycrawler_redis'
#start_url的redis的键
redis_key='mycrawler:start_urls'
#手动制定all_domains，可以不写
allow_domains=["dmoztools.net"]
#和crawl一样,指定url的过滤规则
rules=(
  Rule(LinkExtractor(),callback='parse_page',follow=True)
```

**启动**

```bash
#爬虫名字
scrapy runspider myspider
或(2选1)
#蜘蛛文件名字
scrapy runspider myspider.py
```

redis运行

```cpp
#redis 添加 键:值 "爬取的网址"
redis-c1i lpush guazi:start_urls "http://ww.guazi.com/sjz/dazhong/"
```

### 快速启动爬虫

```python
from scrapy import cmdline

cmdline.execute("scrapy crawl guazicrawl".split())

# import redis
#
# r=redis.StrictRedis()
# r.lpush("myspider:start_urls",[])
```

### 其他参数

- 如果抓取的url不完整，没前面的url，可以使用下面方法

```php
import urllib
a = http://www.baidu.com?123
b = ?456
#在程序中a可以使用response.url(响应地址)
#在pycharm中parse颜色会加深，不过没事
b = urllib.parse.urljoin(a,b)
print("b=%s"%b)
#b=http://www.baidu.com?456
```

### 存多个url或其他东西，可以用列表存储

```python
#比如存图片连接，一个网页中有很多图片连接
item["img_list"] =[]
#extend追加的方式，注意后面用.extract()
item["img_list"].extend(response.xpath('//img[@class="BDE_Image"]/@src').extract())
```