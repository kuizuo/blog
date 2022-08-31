---
id: frida-java-encryption-algorithm
slug: /frida-java-encryption-algorithm
title: Frida java层自吐加密算法
date: 2021-02-10
authors: kuizuo
tags: [frida, app, hook]
keywords: [frida, app, hook]
---

<!-- truncate -->

## 代码

针对 java 层加密算法，能 hook 到 java 自带的加密函数库

```javascript
const config = {
  showStacks: false,
  showDivider: true,
}

Java.perform(function () {
  // console.log('frida 已启动');
  function showStacks(name = '') {
    if (config.showStacks) {
      console.log(Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new(name)))
    }
  }

  function showDivider(name = '') {
    if (config.showDivider) {
      console.log(`==============================${name}==============================`)
    }
  }

  function showArguments() {
    console.log('arguments: ', ...arguments)
  }

  const ByteString = Java.use('com.android.okhttp.okio.ByteString')
  const Encode = {
    toBase64(tag, data) {
      console.log(tag + ' Base64: ', ByteString.of(data).base64())
      // console.log(tag + ' Base64: ', bytesToBase64(data));
    },
    toHex(tag, data) {
      console.log(tag + ' Hex: ', ByteString.of(data).hex())
      // console.log(tag + ' Hex: ', bytesToHex(data));
    },
    toUtf8(tag, data) {
      console.log(tag + ' Utf8: ', ByteString.of(data).utf8())
      // console.log(tag + ' Utf8: ', bytesToString(data));
    },
    toAll(tag, data) {
      Encode.toUtf8(tag, data)
      Encode.toHex(tag, data)
      Encode.toBase64(tag, data)
    },
    toResult(tag, data) {
      Encode.toHex(tag, data)
      Encode.toBase64(tag, data)
    },
  }

  const MessageDigest = Java.use('java.security.MessageDigest')
  {
    let overloads_update = MessageDigest.update.overloads
    for (const overload of overloads_update) {
      overload.implementation = function () {
        const algorithm = this.getAlgorithm()
        showDivider(algorithm)
        showStacks(algorithm)
        Encode.toAll(`${algorithm} update data`, arguments[0])
        return this.update(...arguments)
      }
    }

    let overloads_digest = MessageDigest.digest.overloads
    for (const overload of overloads_digest) {
      overload.implementation = function () {
        const algorithm = this.getAlgorithm()
        showDivider(algorithm)
        showStacks(algorithm)
        const result = this.digest(...arguments)
        if (arguments.length === 1) {
          Encode.toAll(`${algorithm} update data`, arguments[0])
        } else if (arguments.length === 3) {
          Encode.toAll(`${algorithm} update data`, arguments[0])
        }

        Encode.toResult(`${algorithm} digest result`, result)
        return result
      }
    }
  }

  const Mac = Java.use('javax.crypto.Mac')
  {
    Mac.init.overload('java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (key, AlgorithmParameterSpec) {
      return this.init(key, AlgorithmParameterSpec)
    }
    Mac.init.overload('java.security.Key').implementation = function (key) {
      const algorithm = this.getAlgorithm()
      showDivider(algorithm)
      showStacks(algorithm)
      const keyBytes = key.getEncoded()
      Encode.toAll(`${algorithm} init Key`, keyBytes)
      return this.init(...arguments)
    }

    // let overloads_update = Mac.update.overloads;
    // for (const overload of overloads_update) {
    //   overload.implementation = function () {
    //     const algorithm = this.getAlgorithm();
    //     showDivider(algorithm);
    //     showStacks(algorithm);
    //     Encode.toAll(`${algorithm} update data`, arguments[0]);
    //     return this.update(...arguments);
    //   };
    // }

    let overloads_doFinal = Mac.doFinal.overloads
    for (const overload of overloads_doFinal) {
      overload.implementation = function () {
        const algorithm = this.getAlgorithm()
        showDivider(algorithm)
        showStacks(algorithm)
        const result = this.doFinal(...arguments)
        if (arguments.length === 1) {
          Encode.toAll(`${algorithm} update data`, arguments[0])
        } else if (arguments.length === 3) {
          Encode.toAll(`${algorithm} update data`, arguments[0])
        }

        Encode.toResult(`${algorithm} doFinal result`, result)
        return result
      }
    }
  }

  const Cipher = Java.use('javax.crypto.Cipher')
  {
    let overloads_init = Cipher.init.overloads
    for (const overload of overloads_init) {
      overload.implementation = function () {
        const algorithm = this.getAlgorithm()
        showDivider(algorithm)
        showStacks(algorithm)

        if (arguments[0]) {
          const mode = arguments[0]
          console.log(`${algorithm} init mode`, mode)
        }

        if (arguments[1]) {
          const className = JSON.stringify(arguments[1])
          // 安卓10以上私钥是有可能输出不了的
          if (className.includes('OpenSSLRSAPrivateKey')) {
            // const keyBytes = arguments[1];
            // console.log(`${algorithm} init key`, keyBytes);
          } else {
            const keyBytes = arguments[1].getEncoded()
            Encode.toAll(`${algorithm} init key`, keyBytes)
          }
        }

        if (arguments[2]) {
          const className = JSON.stringify(arguments[2])
          if (className.includes('javax.crypto.spec.IvParameterSpec')) {
            const iv = Java.cast(arguments[2], Java.use('javax.crypto.spec.IvParameterSpec'))
            const ivBytes = iv.getIV()
            Encode.toAll(`${algorithm} init iv`, ivBytes)
          } else if (className.includes('java.security.SecureRandom')) {
          }
        }

        return this.init(...arguments)
      }
    }

    // let overloads_update = Cipher.update.overloads;
    // for (const overload of overloads_update) {
    //   overload.implementation = function () {
    //     const algorithm = this.getAlgorithm();
    //     showDivider(algorithm);
    //     showStacks(algorithm);
    //     Encode.toAll(`${algorithm} update data`, arguments[0]);
    //     return this.update(...arguments);
    //   };
    // }

    let overloads_doFinal = Cipher.doFinal.overloads
    for (const overload of overloads_doFinal) {
      overload.implementation = function () {
        const algorithm = this.getAlgorithm()
        showDivider(algorithm)
        showStacks(algorithm)
        const result = this.doFinal(...arguments)
        if (arguments.length === 1) {
          Encode.toAll(`${algorithm} update data`, arguments[0])
        } else if (arguments.length === 3) {
          Encode.toAll(`${algorithm} update data`, arguments[0])
        }

        Encode.toResult(`${algorithm} doFinal result`, result)
        return result
      }
    }
  }

  const Signature = Java.use('java.security.Signature')
  {
    let overloads_update = Signature.update.overloads
    for (const overload of overloads_update) {
      overload.implementation = function () {
        const algorithm = this.getAlgorithm()
        showDivider(algorithm)
        showStacks(algorithm)
        Encode.toAll(`${algorithm} update data`, arguments[0])
        return this.update(...arguments)
      }
    }

    let overloads_sign = Signature.sign.overloads
    for (const overload of overloads_sign) {
      overload.implementation = function () {
        const algorithm = this.getAlgorithm()
        showDivider(algorithm)
        showStacks(algorithm)
        const result = this.sign()
        Encode.toResult(`${algorithm} sign result`, result)
        return this.sign(...arguments)
      }
    }
  }
})
```
