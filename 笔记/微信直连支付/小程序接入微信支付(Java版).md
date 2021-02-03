# 小程序/JSAPI微信支付



## 要点

- 服务商支付：扫码支付、人脸支付

- 直连支付：直接支付

- 所有API请求必须为HTTPS

- 微信支付API v3使用[JSON](http://www.json.org/)作为消息体的数据交换格式。请求须设置HTTP头部：

- ```JAVA
  Content-Type: application/json
  Accept: application/json
  ```

- 【重点】APIv3要求所有请求必须加签名，且签名算法与API版本有区别，下面来详细列举。

  - 微信支付商户API v3要求请求通过HTTP`Authorization`头来传递签名。`Authorization`由**认证类型**和**签名信息**两个部分组成。
  - `Authorization: 认证类型 签名信息`

- 认证类型：固定为 WECHATPAY2-SHA256-RSA2048

- ==方法内所使用的时间戳随机串要保持一致==



## 申请及文档

1. 申请支付
2. ![image-20201207135339137](小程序接入微信支付(Java版).assets/image-20201207135339137.png)
3. 申请商户号，认证，略
4. 申请私钥和秘钥
5. ![img](小程序接入微信支付(Java版).assets/2020040816502868.png)
6. 然后在商户号下方
7. ![image-20201207141230468](小程序接入微信支付(Java版).assets/image-20201207141230468.png)
8. 查看API
9. ![image-20201207141859949](小程序接入微信支付(Java版).assets/image-20201207141859949.png)
10. ![image-20201207141210921](小程序接入微信支付(Java版).assets/image-20201207141210921.png)
11. 我们可以看V2版的介绍
12. ![image-20201207141330774](小程序接入微信支付(Java版).assets/image-20201207141330774.png)
13. 看直连支付
14. ![image-20201209182428900](小程序接入微信支付(Java版).assets/image-20201209182428900.png)
15. 接口文档：https://pay.weixin.qq.com/wiki/doc/apiv3/wxpay/pay/transactions/chapter3_2.shtml

16. **回调接口以及js安全域名要在微信商户平台设置**



## 正式对接

### **接口说明**

#### 后端下单接口

**适用对象：** 直连商户

**请求URL：**https://api.mch.weixin.qq.com/v3/pay/transactions/jsapi

**请求方式：**POST

**接口规则：**https://wechatpay-api.gitbook.io/wechatpay-api-v3



**请求参数**

| 参数名                                                       | 变量         | 类型[长度限制] | 必填 | 描述                                                         |
| :----------------------------------------------------------- | :----------- | :------------- | :--- | :----------------------------------------------------------- |
| 公众号ID                                                     | appid        | string[1,32]   | 是   | body 直连商户申请的公众号或移动应用appid。 示例值：wxd678efh567hg6787 |
| 直连商户号                                                   | mchid        | string[1,32]   | 是   | body 直连商户的商户号，由微信支付生成并下发。 示例值：1230000109 |
| 商品描述                                                     | description  | string[1,127]  | 是   | body 商品描述 示例值：Image形象店-深圳腾大-QQ公仔            |
| 商户订单号                                                   | out_trade_no | string[6,32]   | 是   | body 商户系统内部订单号，只能是数字、大小写字母_-*且在同一个商户号下唯一 示例值：1217752501201407033233368018 |
| 交易结束时间                                                 | time_expire  | string[1,64]   | 否   | body 订单失效时间，遵循[rfc3339](https://tools.ietf.org/html/rfc3339)标准格式，格式为YYYY-MM-DDTHH:mm:ss+TIMEZONE，YYYY-MM-DD表示年月日，T出现在字符串中，表示time元素的开头，HH:mm:ss表示时分秒，TIMEZONE表示时区（+08:00表示东八区时间，领先UTC 8小时，即北京时间）。例如：2015-05-20T13:29:35+08:00表示，北京时间2015年5月20日 13点29分35秒。 示例值：2018-06-08T10:34:56+08:00 |
| 附加数据                                                     | attach       | string[1,128]  | 否   | body 附加数据，在查询API和支付通知中原样返回，可作为自定义参数使用 示例值：自定义数据 |
| 通知地址                                                     | notify_url   | string[1,256]  | 是   | body 通知URL必须为直接可访问的URL，不允许携带查询串。 格式：URL 示例值：https://www.weixin.qq.com/wxpay/pay.php |
| 订单优惠标记                                                 | goods_tag    | string[1,32]   | 否   | body 订单优惠标记 示例值：WXG                                |
| -订单金额                                                    | amount       | object         | 是   | body 订单金额信息                                            |
| 参数名变量类型[长度限制]必填描述总金额totalint是订单总金额，单位为分。 示例值：100货币类型currencystring[1,16]否CNY：人民币，境内商户号仅支持人民币。 示例值：CNY |              |                |      |                                                              |
| -支付者                                                      | payer        | object         | 是   | body 支付者信息                                              |
| 参数名变量类型[长度限制]必填描述用户标识openidstring[1,128]是用户在直连商户appid下的唯一标识。 示例值：oUpF8uMuAJO_M2pxb1Q9zNjWeS6o |              |                |      |                                                              |
| -优惠功能                                                    | detail       | object         | 否   | body 优惠功能                                                |
| 参数名变量类型[长度限制]必填描述订单原价cost_priceint否1、商户侧一张小票订单可能被分多次支付，订单原价用于记录整张小票的交易金额。 2、当订单原价与支付金额不相等，则不享受优惠。 3、该字段主要用于防止同一张小票分多次支付，以享受多次优惠的情况，正常支付订单不必上传此参数。 示例值：608800商品小票IDinvoice_idstring[1,32]否商家小票ID 示例值：微信123+单品列表goods_detailarray否单品列表信息 条目个数限制：【1，undefined】 |              |                |      |                                                              |
| -场景信息                                                    | scene_info   | object         | 否   | body 支付场景描述                                            |
| 参数名变量类型[长度限制]必填描述用户终端IPpayer_client_ipstring[1,45]是调用微信支付API的机器IP，支持IPv4和IPv6两种格式的IP地址。 示例值：14.23.150.211商户端设备号device_idstring[1,32]否商户端设备号（门店号或收银设备ID）。 示例值：013467007045764+商户门店信息store_infoobject否商户门店信息 |              |                |      |                                                              |

返回

```json
{	
  "prepay_id": "wx201410272009395522657a690389285100"
}
```



#### 小程序调起支付

| 参数名             | 变量      | 类型[长度限制] | 必填 | 描述                                                         |
| :----------------- | :-------- | :------------- | :--- | :----------------------------------------------------------- |
| 小程序id           | appId     | string[1,16]   | 是   | 请填写merchant_appid对应的值。 示例值：wx8888888888888888    |
| 时间戳             | timeStamp | string[1,32]   | 是   | 当前的时间，其他详见[时间戳规则](https://pay.weixin.qq.com/wiki/doc/api/jsapi.php?chapter=4_2)。 示例值：1414561699 |
| 随机字符串         | nonceStr  | string[1,32]   | 是   | 随机字符串，不长于32位。推荐[随机数生成算法](https://pay.weixin.qq.com/wiki/doc/api/jsapi.php?chapter=4_3)。 示例值：5K8264ILTKCH16CQ2502SI8ZNMTM67VS |
| 订单详情扩展字符串 | package   | string[1,128]  | 是   | 统一下单接口返回的prepay_id参数值，提交格式如：prepay_id=*** 示例值：prepay_id=wx201410272009395522657a690389285100 |
| 签名方式           | signType  | string[1,32]   | 是   | 签名类型，默认为RSA，仅支持RSA。 示例值：RSA                 |
| 签名               | paySign   | string[1,256]  | 是   | 签名，使用字段appId、timeStamp、nonceStr、package按照[签名生成算法](https://wechatpay-api.gitbook.io/wechatpay-api-v3/qian-ming-zhi-nan-1/qian-ming-sheng-cheng)计算得出的签名值 示例值：oR9d8PuhnIc+YZ8cBHFCwfgpaK9gd7vaRvkYD7rthRAZ\/X+QBhcCYL21N7cHCTUxbQ+EAt6Uy+lwSN22f5YZvI45MLko8Pfso0jm46v5hqcVwrk6uddkGuT+Cdvu4WBqDzaDjnNa5UK3GfE1Wfl2gHxIIY5lLdUgWFts17D4WuolLLkiFZV+JSHMvH7eaLdT9N5GBovBwu5yYKUR7skR8Fu+LozcSqQixnlEZUfyE55feLOQTUYzLmR9pNtPbPsu6WVhbNHMS3Ss2+AehHvz+n64GDmXxbX++IOBvm2olHu3PsOUGRwhudhVf7UcGcunXt8cqNjKNqZLhLw4jq\/xDg== |

### 代码及流程

##### 支付接口及逻辑处理

- 设置请求体

  - 参考上面后端下单接口，看所需要的参数，转换成json

- 生成签名

  - ```java
    	/**
         * 签名生成
         *
         * @param method    请求方法
         * @param url       请求API的HttpUrl对象
         * @param body      请求体json
         * @param mchId     商户号
         * @param filename  商户证书私钥名字(文件夹+名字)
         * @param serialNo  商户API证书序列号
         * @param timestamp 请求时间戳
         * @return
         * @throws Exception
         */
        public static Map<String, String> getAuthorizationToken(String method, HttpUrl url, String body, String mchId, String filename, String serialNo, long timestamp)
                throws NoSuchAlgorithmException, IOException, SignatureException, InvalidKeyException {
            String nonceStr = RandomStringUtils.randomAlphanumeric(32).toUpperCase();
            //构造签名串
            String message = buildRequestSignatureStr(method, url, timestamp, nonceStr, body);
            //String私钥转私钥PrivateKey
            PrivateKey privateKey1 = getPrivateKey(filename);
            //对私钥进行签名，计算签名值
            String signature = sign(message.getBytes(StandardCharsets.UTF_8), privateKey1);
            Map<String, String> map = new HashMap<>();
            map.put("authorization", SCHEMA + " " + "mchid=\"" + mchId + "\","
                    + "serial_no=\"" + serialNo + "\","
                    + "nonce_str=\"" + nonceStr + "\","
                    + "timestamp=\"" + timestamp + "\","
                    + "signature=\"" + signature + "\"");
            map.put("nonceStr", nonceStr);
            return map;
        }
    ```
  
- 设置请求头

  - ```java
    headParams.put("Accept", "application/json");
    headParams.put("Content-Type", "application/json");
    headParams.put("User-Agent", request.getHeader("User-Agent"));
    headParams.put("Authorization", authorizationMap.get("authorization"));
    ```

- 下单请求

- 自己的逻辑

- ---

- 判断证书是否匹配
  - 下载证书
  - 设置缓存
  
- 验签

  - 构造签名串

- ```java
  /**
       * 支付下单返回的签名验证
       * 回调验签 @see{com.yanbo.springboot.commons.utils.wxpay.apiv3.WxPayApiV3NotifyUtils#doVerify(java.lang.String, java.lang.String, javax.servlet.http.HttpServletRequest)}
       *
       * @param response 响应对象
       * @return
       * @throws Exception
       */
      public static Object validate(CloseableHttpResponse response, HttpServletRequest request) throws Exception {
          log.trace("**********************do validate***********************");
          // 判断是否使用同一个微信平台证书
          String wechatpaySerial = response.getFirstHeader("Wechatpay-Serial").getValue();
          log.trace("所使用的微信平台证书序列号-Wechatpay-Serial:" + wechatpaySerial);
  
          if (WxPayApiV3Contants.CERTIFICATE_MAP.isEmpty()) {
              log.trace("CERTIFITE_MAP is null");
              //如果是空的,代表第一次执行,读取文件
              File list = new File("resource/cert/platform");
              if (!list.exists()) {
                  boolean mkdirs = list.mkdirs();
                  log.trace("mkdir is : " + mkdirs);
                  if (!mkdirs) {
                      log.error("创建cert文件夹失败,程序或将无法正常运行,请及时介入修复");
                      // todo 每个error发送邮件和短信
                  }
              }
              String[] names = list.list();
              assert names != null;
              if (names.length != 0) {
                  for (String name : names) {
                      //构造证书
                      Certificate wechatpayCert = getCertificate("resource/cert/platform/" + name);
                      WxPayApiV3Contants.CERTIFICATE_MAP.put(name.replaceAll("\\.pem|wechatpay_", ""), wechatpayCert);
                  }
              } else {
                  downloadCertificateAndiDecrypt(request, wechatpaySerial);
              }
          }
          log.trace("是否包含微信平台证书: " + WxPayApiV3Contants.CERTIFICATE_MAP.containsKey(wechatpaySerial));
          //判断是或否含有证书(是否匹配)
          while (!WxPayApiV3Contants.CERTIFICATE_MAP.containsKey(wechatpaySerial)) {
              downloadCertificateAndiDecrypt(request, wechatpaySerial);
          }
  
          //需要校验的签名
          String wechatpaySignature = response.getFirstHeader("Wechatpay-Signature").getValue();
          log.trace("Wechatpay-Signature: " + wechatpaySignature);
          //响应时戳
          String wechatpayTimestamp = response.getFirstHeader("Wechatpay-Timestamp").getValue();
          log.trace("Wechatpay-Timestamp: " + wechatpayTimestamp);
          //响应随机串
          String wecahtpayNonce = response.getFirstHeader("Wechatpay-Nonce").getValue();
          log.trace("Wechatpay-Nonce: " + wecahtpayNonce);
          //微信响应体
          String responseBodyStr = EntityUtils.toString(response.getEntity(), "utf-8");
          log.trace("responseBodyStr: " + responseBodyStr);
          Set<Map.Entry<String, Certificate>> entries = WxPayApiV3Contants.CERTIFICATE_MAP.entrySet();
          for (Map.Entry<String, Certificate> entry : entries) {
              String key = entry.getKey();
              Certificate value = entry.getValue();
              System.out.println("k: " + key + "v: " + value.getPublicKey().toString());
          }
          //验签
          boolean isPassVerifySignature = WxPayApiV3Utils.doVerifySignature(WxPayApiV3Contants.CERTIFICATE_MAP.get(wechatpaySerial)
                  , wechatpaySignature, wechatpayTimestamp, wecahtpayNonce, responseBodyStr);
          log.trace("isPassVerifySignature: " + isPassVerifySignature);
          return isPassVerifySignature ? responseBodyStr : null;
      }
  
  	/**
       * 支付下单返回的签名验证
       *
       * @param wxPayCertificate   微信平台证书对象
       * @param wechatpaySignature 微信待验证签名
       * @param wechatpayTimestamp 响应时间戳
       * @param wechatpayNonce     响应随机数
       * @param responseBody       响应体
       * @return 是否验证成功
       */
      static boolean doVerifySignature(Certificate wxPayCertificate, String wechatpaySignature, String wechatpayTimestamp, String wechatpayNonce
              , String responseBody) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
          //构造验签名串
          String responseSigntureStr = buildResponseSignatureStr(wechatpayTimestamp, wechatpayNonce, responseBody);
          Signature signer = Signature.getInstance("SHA256withRSA");
          signer.initVerify(wxPayCertificate);
          signer.update(responseSigntureStr.getBytes(StandardCharsets.UTF_8));
          return signer.verify(Base64Utils.decodeFromString(wechatpaySignature));
      }
  
  	/**
       * 构造验签名串
       *
       * @param wechatpayTimestamp 响应时间戳
       * @param wecahtpayNonce     响应随机数
       * @param responseBody       响应体
       * @return 签名串
       */
      private static String buildResponseSignatureStr(String wechatpayTimestamp, String wecahtpayNonce
              , String responseBody) {
          return Stream.of(wechatpayTimestamp, wecahtpayNonce, responseBody)
                  .collect(Collectors.joining("\n", "", "\n"));
      }
  ```

- 构造前端签名并返回前端

- ```java
  //@NotNull
      private Object doSendAndValiatedResponse(String json, Map<String, String> headParams, long timestamp, Map<String, ?> authorizationMap, HttpServletRequest request) throws Exception {
          log.trace("**************************doSendAndValiatedResponse*************************");
          String responseBody = null;
          try (
                  CloseableHttpResponse response = HttpClientUtils.postJsonResponse(WxPayApiV3Contants.PLACE_AN_ORDER_URL, json, headParams);
          ) {
              // 验签
              Object o = WxPayApiV3Utils.validate(response, request);
              if (o instanceof Result || o == null) {
                  return o;
              }
              responseBody = (String) o;
          } catch (IOException e) {
              e.printStackTrace();
          }
  
          assert responseBody != null && !"".equals(responseBody);
          // 返回前端的数据
          @SuppressWarnings("unchecked")
          Map<String, Object> postResult = JacksonUtils.jsonToPojo(responseBody, Map.class);
          assert postResult != null;
          postResult.put("appId", WxPayApiV3Contants.APPID);
          postResult.put("timeStamp", timestamp);
          String nonceStr = (String) authorizationMap.get("nonceStr");
          postResult.put("nonceStr", nonceStr);
          String packageStr = "prepay_id=" + postResult.get("prepay_id");
          postResult.put("package", packageStr);
          postResult.keySet().remove("prepay_id");
          String paySign = WxPayApiV3Utils.getPaySign(WxPayApiV3Contants.APPID, timestamp, nonceStr, packageStr, WxPayApiV3Contants.APIV3_PUBLICKEY_FILENAME);
          postResult.put("paySign", paySign);
          return postResult;
      }
  
  /**
       * 构造前端支付签名
       *
       * @param appId      小程序id
       * @param timestamp  时间戳
       * @param nonceStr   随机字符串
       * @param packageStr
       * @param filename   文件目录+文件名
       * @return
       * @throws Exception
       */
      public static String getPaySign(String appId, long timestamp, String nonceStr, String packageStr
              , String filename) throws Exception {
          //构造签名串
          String message = buildPaySign(appId, timestamp, nonceStr, packageStr);
          //String私钥转私钥PrivateKey
          PrivateKey privateKey1 = getPrivateKey(filename);
          //对私钥进行签名
          return sign(message.getBytes(StandardCharsets.UTF_8), privateKey1);
      }
  
      private static String buildPaySign(String appId, long timestamp, String nonceStr, String packageStr) {
          return Stream.of(appId, String.valueOf(timestamp), nonceStr, packageStr)
                  .collect(Collectors.joining("\n", "", "\n"));
      }
  ```

- ~~前端调起支付~~

- 回调接受请求体

  - **回调接口以及js安全域名要在微信商户平台设置**

- 判断证书是否匹配
  
  - 惰性加载-自动更新证书
  
  - ```java
    /**
         * 回调时自动更新微信平台证书 惰性加载
         *
         * @param request
         * @param wechatpaySerial 微信平台序列号
         * @throws NoSuchAlgorithmException
         * @throws IOException
         * @throws InvalidKeySpecException
         * @throws SignatureException
         * @throws InvalidKeyException
         */
        public static void autoupdateCertificate(HttpServletRequest request, String wechatpaySerial) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException {
            //如果没有平台证书或者证书序列号不匹配，则获取平台证书
            WxPayApiV3Utils.downloadCertificateAndiDecrypt(request, wechatpaySerial);
        }
    
    /**
         * 下载和解密证书
         *
         * @param request
         * @param wechatpaySerial 微信证书序列号
         * @throws NoSuchAlgorithmException
         * @throws IOException
         * @throws InvalidKeySpecException
         * @throws SignatureException
         * @throws InvalidKeyException
         */
        public static void downloadCertificateAndiDecrypt(HttpServletRequest request, String wechatpaySerial) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException {
            String wxCertificatesNewJson = WxPayApiV3Utils.downloadWxPayCertificate(request);
            log.trace("新的微信平台证书密串为: " + wxCertificatesNewJson);
            WxCertificatesResource wxCertificatesResource = JacksonUtils.jsonToPojo(wxCertificatesNewJson, WxCertificatesResource.class);
            assert wxCertificatesResource != null;
            List<WxCertificatesResource.WxCertificateData> wxCertificateDataList = wxCertificatesResource.getData();
            // 循环数组校把所有证书写到本地及map
            for (WxCertificatesResource.WxCertificateData wxCertificateData : wxCertificateDataList) {
                // 解密
                WxCertificatesResource.EncryptCertificate encryptCertificate = wxCertificateData.getEncrypt_certificate();
                String wxPayCertificateAllStr = WxPayApiV3Utils.decryptResponseBody(WxPayApiV3Contants.APIV3_KEY
                        , encryptCertificate.getAssociated_data()
                        , encryptCertificate.getNonce()
                        , encryptCertificate.getCiphertext());
                //解密后就是证书
                log.trace("微信证书api解密字符串-wxCertificateStr: " + wxPayCertificateAllStr);
                // 输出文件,写入到map
                WxPayApiV3Utils.writeToCertificate(wechatpaySerial, wxPayCertificateAllStr);
            }
        }
    ```
  
- 验证签名

  - 上面一样的方法

  - ```java
    /**
         * 回调的验证签名
         * 支付下单返回的签名验证@see{com.yanbo.sellfood.portalweb.controller.WxPayController#doValidated(org.apache.http.client.methods.CloseableHttpResponse)}
         *
         * @param requestJsonBody  请求体json
         * @param wxPayCertificate 微信平台证书对象
         * @param request
         * @return
         * @throws Exception
         */
        private static boolean verify(String requestJsonBody, Certificate wxPayCertificate, HttpServletRequest request)
                throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
            //微信验签字段
            log.trace("requestBody is : " + requestJsonBody);
            String wechatpaySignature = request.getHeader("wechatpay-signature");
            log.trace("wechatpay-signature: " + wechatpaySignature);
            String wechatpayTimestamp = request.getHeader("wechatpay-timestamp");
            log.trace("wechatpay-timestamp: " + wechatpayTimestamp);
            String wechatpayNonce = request.getHeader("wechatpay-nonce");
            log.trace("wechatpay-nonce: " + wechatpayTimestamp);
            //微信验签
            boolean isVerify = WxPayApiV3Utils.doVerifySignature(wxPayCertificate, wechatpaySignature, wechatpayTimestamp
                    , wechatpayNonce, requestJsonBody);
            log.trace("isVerify : " + isVerify);
            return isVerify;
        }
    ```

  - 

- 解密资源

- ```java
  /**
       * 微信支付回调
       */
      @RequestMapping("/payCallBack")
      @Transactional(rollbackFor = Exception.class)
      public Map<String, Object> payCallBack(@RequestBody Map<String, Object> map, HttpServletRequest request)
              throws NoSuchAlgorithmException, SignatureException, IOException, InvalidKeySpecException, InvalidKeyException, ParseException {
          log.debug("***********************do payCallback***********************");
          //输出请求头
          if (log.isTraceEnabled()) {
              Enumeration<String> requestHeaderNames = request.getHeaderNames();
              while (requestHeaderNames.hasMoreElements()) {
                  String name = requestHeaderNames.nextElement();
                  String value = request.getHeader(name);
                  log.trace("requestHeader: " + name + ": " + value);
              }
  
          }
          //微信平台证书序列号
          String wechatpaySerial = request.getHeader("wechatpay-serial");
          log.trace("wechatpay-serial: " + wechatpaySerial);
          // 先校对平台证书序列号，再进行验签。
          // 自动更新微信平台证书 惰性加载
          while (!WxPayApiV3Contants.CERTIFICATE_MAP.containsKey(wechatpaySerial)) {
              WxPayApiV3NotifyUtils.autoupdateCertificate(request, wechatpaySerial);
          }
          // 验证签名
          boolean isVerify = WxPayApiV3NotifyUtils.verify(map, WxPayApiV3Contants.CERTIFICATE_MAP.get(wechatpaySerial), request);
          //最后返回map告诉微信正常接收到消息，否则微信会轮询该接口
          // 验签成功和微信平台证书序列号通过
          if (isVerify) {
              //如果支付成功
              if (StringUtils.equals("TRANSACTION.SUCCESS", (String) map.get("event_type"))) {
                  //获取通知资源数据
                  @SuppressWarnings({"unchecked", "AlibabaUndefineMagicConstant"})
                  Map<String, String> resource = (Map<String, String>) map.get("resource");
                  //解密资源数据
                  String notifyResourceStr = WxPayApiV3Utils.decryptResponseBody(WxPayApiV3Contants.APIV3_KEY, resource.get("associated_data"), resource.get("nonce"), resource.get("ciphertext"));
                  log.trace("notifyResouceStr is : " + notifyResourceStr);
                  WxPayNotifyResource wxPayNotifyResource = JacksonUtils.jsonToPojo(notifyResourceStr, WxPayNotifyResource.class);
  
                  //如果付款成功
                  assert wxPayNotifyResource != null;
                  //更新订单状态
                  ordersService.updateOrder(wxPayNotifyResource);
                  //更新商品数量 TODO ： 正确流程应该是订单下单后锁定商品数量，订单取消时放开，要使用轮询定时计划
                  comService.updateCommoditiesCount(wxPayNotifyResource.getOut_trade_no());
              } else {
                  log.error("微信返回支付错误摘要: " + map.get("summary"));
              }
              //通知微信正常接收到消息,否则微信会轮询该接口
              map.clear();
              map.put("code", "SUCCESS");
              map.put("message", "");
              return map;
          } else {
              log.error("微信平台证书序列号不一致或验签失败");
          }
          return map;
      }
  ```

- 更新订单状态









## 代码参考

文件在此文件图片目录下

```java
package com.yanbo.sellfood.portalweb.controller;

import com.alibaba.dubbo.config.annotation.Reference;
import com.yanbo.sellfood.portalinterface.service.CommoditiesService;
import com.yanbo.sellfood.portalinterface.service.OrdersService;
import com.yanbo.springboot.commons.pojo.domain.Result;
import com.yanbo.springboot.commons.pojo.po.Orders;
import com.yanbo.springboot.commons.pojo.wxpay.apiv3.WxPayNotifyResource;
import com.yanbo.springboot.commons.utils.Contants;
import com.yanbo.springboot.commons.utils.HttpClientUtils;
import com.yanbo.springboot.commons.utils.JacksonUtils;
import com.yanbo.springboot.commons.utils.ParamUtils;
import com.yanbo.springboot.commons.utils.wxpay.apiv3.WxPayApiV3Contants;
import com.yanbo.springboot.commons.utils.wxpay.apiv3.WxPayApiV3NotifyUtils;
import com.yanbo.springboot.commons.utils.wxpay.apiv3.WxPayApiV3Utils;
import lombok.extern.slf4j.Slf4j;
import okhttp3.HttpUrl;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * @author ChihoiTse
 * @jdk 8
 * @description:
 * @date 2020/12/10 0010 - 10:18
 */

@RestController
@RequestMapping("/api/v1")
@Slf4j
public class WxPayController {

    @Reference
    private OrdersService ordersService;

    @Reference
    private CommoditiesService comService;

    /**
     * 微信支付回调
     */
    @RequestMapping("/payCallBack")
    @Transactional(rollbackFor = Exception.class)
    public Map<String, Object> payCallBack(@RequestBody Map<String, Object> map, HttpServletRequest request)
            throws NoSuchAlgorithmException, SignatureException, IOException, InvalidKeySpecException, InvalidKeyException, ParseException {
        log.debug("***********************do payCallback***********************");
        //输出请求头
        if (log.isTraceEnabled()) {
            Enumeration<String> requestHeaderNames = request.getHeaderNames();
            while (requestHeaderNames.hasMoreElements()) {
                String name = requestHeaderNames.nextElement();
                String value = request.getHeader(name);
                log.trace("requestHeader: " + name + ": " + value);
            }

        }
        //微信平台证书序列号
        String wechatpaySerial = request.getHeader("wechatpay-serial");
        log.trace("wechatpay-serial: " + wechatpaySerial);
        // 先校对平台证书序列号，再进行验签。
        // 自动更新微信平台证书 惰性加载
        while (!WxPayApiV3Contants.CERTIFICATE_MAP.containsKey(wechatpaySerial)) {
            WxPayApiV3NotifyUtils.autoupdateCertificate(request, wechatpaySerial);
        }
        // 验证签名
        boolean isVerify = WxPayApiV3NotifyUtils.verify(map, WxPayApiV3Contants.CERTIFICATE_MAP.get(wechatpaySerial), request);
        //最后返回map告诉微信正常接收到消息，否则微信会轮询该接口
        // 验签成功和微信平台证书序列号通过
        if (isVerify) {
            //如果支付成功
            if (StringUtils.equals("TRANSACTION.SUCCESS", (String) map.get("event_type"))) {
                //获取通知资源数据
                @SuppressWarnings({"unchecked", "AlibabaUndefineMagicConstant"})
                Map<String, String> resource = (Map<String, String>) map.get("resource");
                //解密资源数据
                String notifyResourceStr = WxPayApiV3Utils.decryptResponseBody(WxPayApiV3Contants.APIV3_KEY, resource.get("associated_data"), resource.get("nonce"), resource.get("ciphertext"));
                log.trace("notifyResouceStr is : " + notifyResourceStr);
                WxPayNotifyResource wxPayNotifyResource = JacksonUtils.jsonToPojo(notifyResourceStr, WxPayNotifyResource.class);

                //如果付款成功
                assert wxPayNotifyResource != null;
                //更新订单状态
                //TODO:测试原子性
                ordersService.updateOrder(wxPayNotifyResource);
                //更新商品数量 TODO ： 正确流程应该是订单下单后锁定商品数量，订单取消时放开，要使用轮询定时计划
                comService.updateCommoditiesCount(wxPayNotifyResource.getOut_trade_no());
            } else {
                log.error("微信返回支付错误摘要: " + map.get("summary"));
            }
            //通知微信正常接收到消息,否则微信会轮询该接口
            map.clear();
            map.put("code", "SUCCESS");
            map.put("message", "");
            return map;
        } else {
            log.error("微信平台证书序列号不一致或验签失败");
        }
        return map;
    }

    /**
     * 微信支付接口
     * <p>
     * {@docRoot https://pay.weixin.qq.com/wiki/doc/apiv3/wxpay/pay/transactions/chapter3_2.shtml}
     * <p>
     *
     * @param params 参数
     *               out_trade_no       商户订单号
     *               skey               用戶自定义登录态
     * @return 公共错误码
     * 202	USERPAYING	            用户支付中，需要输入密码	等待5秒，然后调用被扫订单结果查询API，查询当前订单的不同状态，决定下一步的操作
     * 403	TRADE_ERROR	            交易错误	                因业务原因交易失败，请查看接口返回的详细信息
     * 500	SYSTEMERROR	            系统错误	                系统异常，请用相同参数重新调用
     * 401	SIGN_ERROR	            签名错误	                请检查签名参数和方法是否都符合签名算法要求
     * 403	RULELIMIT	            业务规则限制	            因业务规则限制请求频率，请查看接口返回的详细信息
     * 400	PARAM_ERROR	            参数错误	                请根据接口返回的详细信息检查请求参数
     * 403	OUT_TRADE_NO_USED	    商户订单号重复	        请核实商户订单号是否重复提交
     * 404	ORDERNOTEXIST	        订单不存在	            请检查订单是否发起过交易
     * 400	ORDER_CLOSED	        订单已关闭	            当前订单已关闭，请重新下单
     * 500	OPENID_MISMATCH	        openid和appid不匹配	    请确认openid和appid是否匹配
     * 403	NOTENOUGH	            余额不足	                用户帐号余额不足，请用户充值或更换支付卡后再支付
     * 403	NOAUTH	                商户无权限	            请商户前往申请此接口相关权限
     * 400	MCH_NOT_EXISTS	        商户号不存在	            请检查商户号是否正确
     * 500	INVALID_TRANSACTIONID	订单号非法	            请检查微信支付订单号是否正确
     * 400	INVALID_REQUEST	        无效请求	                请根据接口返回的详细信息检查
     * 429	FREQUENCY_LIMITED	    频率超限	                请降低请求接口频率
     * 500	BANKERROR	            银行系统异常	            银行系统异常，请用相同参数重新调用
     * 400	APPID_MCHID_NOT_MATCH	appid和mch_id不匹配	    请确认appid和mch_id是否匹配
     * 403	ACCOUNTERROR	        账号异常	                用户账号异常，无需更多操作
     */
    @PostMapping("/pay")
    @SuppressWarnings("unchecked")
    public Object pay(@RequestBody Map<String, Object> params, HttpServletRequest request, HttpSession session) throws Exception {
        log.debug("***********************do pay***********************");
        ParamUtils.notNull(params, new String[]{"out_trade_no", "skey"});

        String openid = (String) session.getAttribute(params.get("skey") + ":openid");
        String sessionKey = (String) session.getAttribute(params.get("skey") + ":sessionKey");
        log.trace("openid is : " + openid);
        log.trace("sessionKey is : " + sessionKey);
        if (StringUtils.isBlank(openid) || StringUtils.isBlank(sessionKey)) {
            return Result.builder().code(Contants.CODE_40007).msg(Contants.CODE_40007_MSG).build();
        }
        long timestamp = System.currentTimeMillis() / 1000;
        //设置请求体
        params.keySet().remove("skey");
        String json = setPlayloadBody(params, openid);
        log.trace("请求参数为：" + json);
        // 生成签名
        Map<String, String> authorizationMap = WxPayApiV3Utils.getAuthorizationToken("POST", HttpUrl.parse(WxPayApiV3Contants.PLACE_AN_ORDER_URL)
                , json, WxPayApiV3Contants.mchid, WxPayApiV3Contants.APIV3_PUBLICKEY_FILENAME, WxPayApiV3Contants.APIV3_SERIAL_NO, timestamp);
        //设置请求头
        Map<String, String> headParams = setRequestHeader(request, authorizationMap);

        // 下单请求
        Object mapRet = doSendAndValiatedResponse(json, headParams, timestamp, authorizationMap, request);
        log.trace("返回值：" + JacksonUtils.objectToJson(mapRet));
        return mapRet;
    }

    private Map<String, String> setRequestHeader(HttpServletRequest request, Map<String, String> authorizationMap) {
        // 设置请求头
        Map<String, String> headParams = new HashMap<>();
        headParams.put("Accept", "application/json");
        headParams.put("Content-Type", "application/json");
        headParams.put("User-Agent", request.getHeader("User-Agent"));
        headParams.put("Authorization", authorizationMap.get("authorization"));
        return headParams;
    }

    private String setPlayloadBody(Map<String, Object> params, String openid) {
        // 设置参数
        Orders orders = ordersService.findOneOrdersByOrdNumber((String) params.get("out_trade_no"));
        Map<String, Object> map = new HashMap<>();
        map.put("total", orders.getOrdTotalMoney().intValue());
        params.put("amount", map);
        Map<String, Object> map2 = new HashMap<>();
        map2.put("openid", openid);
        params.put("payer", map2);
        params.put("appid", WxPayApiV3Contants.APPID); //公众号id
        params.put("mchid", WxPayApiV3Contants.mchid); //直连商户号
        params.put("notify_url", WxPayApiV3Contants.CALLBACK_URL); // 通知地址
        params.put("description", "广州言博文化-卖菜小程序"); // 商品描述
        return JacksonUtils.objectToJson(params);
    }

    //@NotNull
    private Object doSendAndValiatedResponse(String json, Map<String, String> headParams, long timestamp, Map<String, ?> authorizationMap, HttpServletRequest request) throws Exception {
        log.trace("**************************doSendAndValiatedResponse*************************");
        String responseBody = null;
        try (
                CloseableHttpResponse response = HttpClientUtils.postJsonResponse(WxPayApiV3Contants.PLACE_AN_ORDER_URL, json, headParams);
        ) {
            // 验签
            Object o = WxPayApiV3Utils.validate(response, request);
            if (o instanceof Result || o == null) {
                return o;
            }
            responseBody = (String) o;
        } catch (IOException e) {
            e.printStackTrace();
        }

        assert responseBody != null && !"".equals(responseBody);
        // 返回前端的数据
        @SuppressWarnings("unchecked")
        Map<String, Object> postResult = JacksonUtils.jsonToPojo(responseBody, Map.class);
        assert postResult != null;
        postResult.put("appId", WxPayApiV3Contants.APPID);
        postResult.put("timeStamp", timestamp);
        String nonceStr = (String) authorizationMap.get("nonceStr");
        postResult.put("nonceStr", nonceStr);
        String packageStr = "prepay_id=" + postResult.get("prepay_id");
        postResult.put("package", packageStr);
        postResult.keySet().remove("prepay_id");
        String paySign = WxPayApiV3Utils.getPaySign(WxPayApiV3Contants.APPID, timestamp, nonceStr, packageStr, WxPayApiV3Contants.APIV3_PUBLICKEY_FILENAME);
        postResult.put("paySign", paySign);
        return postResult;
    }

}

```

```java
package com.yanbo.springboot.commons.utils.wxpay.apiv3;

import com.yanbo.springboot.commons.pojo.wxpay.apiv3.WxCertificatesResource;
import com.yanbo.springboot.commons.utils.HttpClientUtils;
import com.yanbo.springboot.commons.utils.JacksonUtils;
import lombok.extern.slf4j.Slf4j;
import okhttp3.HttpUrl;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;
import org.springframework.http.MediaType;
import org.springframework.util.Base64Utils;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * 微信支付apiv3工具类
 * 使用了Lombok
 *
 * @author ChihoiTse
 * @jdk 8
 * @date 2020/12/9 0009 - 13:24
 */
@Slf4j
public class WxPayApiV3Utils {

    @SuppressWarnings("unused")
    private static final String SIGN_TYPE = "RSA"; //签名类型，仅支持HMAC-SHA256。示例值：HMAC-SHA256

    private static final String SCHEMA = "WECHATPAY2-SHA256-RSA2048";

    private static final String SYMBOLS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final Random RANDOM = new SecureRandom();

    /**
     * 签名生成
     *
     * @param method    请求方法
     * @param url       请求API的HttpUrl对象
     * @param body      请求体json
     * @param mchId     商户号
     * @param filename  商户证书私钥名字(文件夹+名字)
     * @param serialNo  商户API证书序列号
     * @param timestamp 请求时间戳
     * @return
     * @throws Exception
     */
    public static Map<String, String> getAuthorizationToken(String method, HttpUrl url, String body, String mchId, String filename, String serialNo, long timestamp)
            throws NoSuchAlgorithmException, IOException, SignatureException, InvalidKeyException {
        String nonceStr = RandomStringUtils.randomAlphanumeric(32).toUpperCase();
        //构造签名串
        String message = buildRequestSignatureStr(method, url, timestamp, nonceStr, body);
        //String私钥转私钥PrivateKey
        PrivateKey privateKey1 = getPrivateKey(filename);
        //对私钥进行签名，计算签名值
        String signature = sign(message.getBytes(StandardCharsets.UTF_8), privateKey1);
        Map<String, String> map = new HashMap<>();
        map.put("authorization", SCHEMA + " " + "mchid=\"" + mchId + "\","
                + "serial_no=\"" + serialNo + "\","
                + "nonce_str=\"" + nonceStr + "\","
                + "timestamp=\"" + timestamp + "\","
                + "signature=\"" + signature + "\"");
        map.put("nonceStr", nonceStr);
        return map;
    }

    /**
     * 计算签名值
     *
     * @param message
     * @param privateKey 商户私钥
     * @return
     */
    private static String sign(byte[] message, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(privateKey);
        sign.update(message);

        return Base64.getEncoder().encodeToString(sign.sign());
    }

    private static String buildRequestSignatureStr(String method, HttpUrl url, long timestamp, String nonceStr, String body) {
        String canonicalUrl = url.encodedPath();
        if (url.encodedQuery() != null) {
            canonicalUrl += "?" + url.encodedQuery();
        }

        return Stream.of(method, canonicalUrl, String.valueOf(timestamp), nonceStr, body).collect(Collectors.joining("\n", "", "\n"));
        /*return method + "\n"
                + canonicalUrl + "\n"
                + timestamp + "\n"
                + nonceStr + "\n"
                + body + "\n";*/
    }

    /**
     * 获取私钥。
     *
     * @param filename 私钥文件路径  (required)
     * @return 私钥对象
     */
    private static PrivateKey getPrivateKey(String filename) throws IOException {

        String content = new String(Files.readAllBytes(Paths.get(filename)), StandardCharsets.UTF_8);
        try {
            String privateKey = content.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");

            KeyFactory kf = KeyFactory.getInstance("RSA");
            // todo return kf.generatePrivate(new PKCS8EncodedKeySpec((new BASE64Decoder()).decodeBuffer(key)));
            return kf.generatePrivate(
                    new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey)));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("当前Java环境不支持RSA", e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("无效的密钥格式");
        }
    }

    /**
     * 获取随机字符串 Nonce Str
     *
     * @return String 随机字符串
     */
    private static String generateNonceStr() {
        char[] nonceChars = new char[32];
        for (int index = 0; index < nonceChars.length; ++index) {
            nonceChars[index] = SYMBOLS.charAt(RANDOM.nextInt(SYMBOLS.length()));
        }
        return new String(nonceChars);
    }

    /**
     * 支付下单返回的签名验证
     * 回调验签 @see{com.yanbo.springboot.commons.utils.wxpay.apiv3.WxPayApiV3NotifyUtils#doVerify(java.lang.String, java.lang.String, javax.servlet.http.HttpServletRequest)}
     *
     * @param response 响应对象
     * @return
     * @throws Exception
     */
    public static Object validate(CloseableHttpResponse response, HttpServletRequest request) throws Exception {
        log.trace("**********************do validate***********************");
        // 判断是否使用同一个微信平台证书
        String wechatpaySerial = response.getFirstHeader("Wechatpay-Serial").getValue();
        log.trace("所使用的微信平台证书序列号-Wechatpay-Serial:" + wechatpaySerial);

        if (WxPayApiV3Contants.CERTIFICATE_MAP.isEmpty()) {
            log.trace("CERTIFITE_MAP is null");
            //如果是空的,代表第一次执行,读取文件
            File list = new File("resource/cert/platform");
            if (!list.exists()) {
                boolean mkdirs = list.mkdirs();
                log.trace("mkdir is : " + mkdirs);
                if (!mkdirs) {
                    log.error("创建cert文件夹失败,程序或将无法正常运行,请及时介入修复");
                    // todo 每个error发送邮件和短信
                }
            }
            String[] names = list.list();
            assert names != null;
            if (names.length != 0) {
                for (String name : names) {
                    //构造证书
                    Certificate wechatpayCert = getCertificate("resource/cert/platform/" + name);
                    WxPayApiV3Contants.CERTIFICATE_MAP.put(name.replaceAll("\\.pem|wechatpay_", ""), wechatpayCert);
                }
            } else {
                downloadCertificateAndiDecrypt(request, wechatpaySerial);
            }
        }
        log.trace("是否包含微信平台证书: " + WxPayApiV3Contants.CERTIFICATE_MAP.containsKey(wechatpaySerial));
        //判断是或否含有证书(是否匹配)
        while (!WxPayApiV3Contants.CERTIFICATE_MAP.containsKey(wechatpaySerial)) {
            downloadCertificateAndiDecrypt(request, wechatpaySerial);
        }

        //需要校验的签名
        String wechatpaySignature = response.getFirstHeader("Wechatpay-Signature").getValue();
        log.trace("Wechatpay-Signature: " + wechatpaySignature);
        //响应时戳
        String wechatpayTimestamp = response.getFirstHeader("Wechatpay-Timestamp").getValue();
        log.trace("Wechatpay-Timestamp: " + wechatpayTimestamp);
        //响应随机串
        String wecahtpayNonce = response.getFirstHeader("Wechatpay-Nonce").getValue();
        log.trace("Wechatpay-Nonce: " + wecahtpayNonce);
        //微信响应体
        String responseBodyStr = EntityUtils.toString(response.getEntity(), "utf-8");
        log.trace("responseBodyStr: " + responseBodyStr);
        Set<Map.Entry<String, Certificate>> entries = WxPayApiV3Contants.CERTIFICATE_MAP.entrySet();
        for (Map.Entry<String, Certificate> entry : entries) {
            String key = entry.getKey();
            Certificate value = entry.getValue();
            System.out.println("k: " + key + "v: " + value.getPublicKey().toString());
        }
        //验签
        boolean isPassVerifySignature = WxPayApiV3Utils.doVerifySignature(WxPayApiV3Contants.CERTIFICATE_MAP.get(wechatpaySerial)
                , wechatpaySignature, wechatpayTimestamp, wecahtpayNonce, responseBodyStr);
        log.trace("isPassVerifySignature: " + isPassVerifySignature);
        return isPassVerifySignature ? responseBodyStr : null;
    }

    /**
     * 下载微信平台证书
     *
     * @param request
     * @return 证书密串
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeySpecException
     * @throws SignatureException
     * @throws InvalidKeyException
     */
    public static String downloadWxPayCertificate(HttpServletRequest request) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        Map<String, String> headMap = new HashMap<>();
        //生成签名
        long timestamp = System.currentTimeMillis() / 1000;
        Map<String, String> authorizationMap = WxPayApiV3Utils.getAuthorizationToken("GET", HttpUrl.parse(WxPayApiV3Contants.CERTIFICATES_URL)
                , "", WxPayApiV3Contants.mchid, WxPayApiV3Contants.APIV3_PUBLICKEY_FILENAME
                , WxPayApiV3Contants.APIV3_SERIAL_NO, timestamp);
        headMap.put("Authorization", authorizationMap.get("authorization"));
        headMap.put("Accept", MediaType.APPLICATION_JSON_VALUE);
        headMap.put("User-Agent", request.getHeader("User-Agent"));
        return HttpClientUtils.get(WxPayApiV3Contants.CERTIFICATES_URL, headMap);
    }

    /**
     * 微信平台证书写入到文件和缓存
     *
     * @param wechatpaySerial     微信平台序列号
     * @param wxPayCertificateStr 微信平台证书
     */
    public static void writeToCertificate(String wechatpaySerial, String wxPayCertificateStr) {
        // TODO: 删除旧证书文件
        File file = new File("resource/cert/platform/" + "wechatpay_" + wechatpaySerial + ".pem");
        if (!file.exists()) {
            if (file.isDirectory()) {
                boolean isDelete = file.delete();
                if (!isDelete) {
                    log.warn("文件删除失败,将导致文件写出失败。请尽快介入修复");
                }
            }
            boolean isNewFile = false;
            try {
                isNewFile = file.createNewFile();
            } catch (IOException e) {
                log.warn("文件创建失败,将导致文件写出失败。请尽快介入修复");
            }
            if (!isNewFile) {
                log.warn("文件创建失败,将导致文件写出失败。请尽快介入修复");
            }
        }

        try (PrintStream ps = new PrintStream(file);) {
            ps.print(wxPayCertificateStr);
        } catch (FileNotFoundException e) {
            log.warn("找不到文件,请尽快介入修复");
        }
        //构造证书
        Certificate wxPayCertificate = WxPayApiV3Utils.getCertificate("resource/cert/platform/" + "wechatpay_" + wechatpaySerial + ".pem");
        //k:证书序列号,v:证书公钥对象
        WxPayApiV3Contants.CERTIFICATE_MAP.put(wechatpaySerial, wxPayCertificate);
    }

    /**
     * 下载和解密证书
     *
     * @param request
     * @param wechatpaySerial 微信证书序列号
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeySpecException
     * @throws SignatureException
     * @throws InvalidKeyException
     */
    public static void downloadCertificateAndiDecrypt(HttpServletRequest request, String wechatpaySerial) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        String wxCertificatesNewJson = WxPayApiV3Utils.downloadWxPayCertificate(request);
        log.trace("新的微信平台证书密串为: " + wxCertificatesNewJson);
        WxCertificatesResource wxCertificatesResource = JacksonUtils.jsonToPojo(wxCertificatesNewJson, WxCertificatesResource.class);
        assert wxCertificatesResource != null;
        List<WxCertificatesResource.WxCertificateData> wxCertificateDataList = wxCertificatesResource.getData();
        // 循环数组校把所有证书写到本地及map
        for (WxCertificatesResource.WxCertificateData wxCertificateData : wxCertificateDataList) {
            // 解密
            WxCertificatesResource.EncryptCertificate encryptCertificate = wxCertificateData.getEncrypt_certificate();
            String wxPayCertificateAllStr = WxPayApiV3Utils.decryptResponseBody(WxPayApiV3Contants.APIV3_KEY
                    , encryptCertificate.getAssociated_data()
                    , encryptCertificate.getNonce()
                    , encryptCertificate.getCiphertext());
            //解密后就是证书
            log.trace("微信证书api解密字符串-wxCertificateStr: " + wxPayCertificateAllStr);
            // 输出文件,写入到map
            WxPayApiV3Utils.writeToCertificate(wechatpaySerial, wxPayCertificateAllStr);
        }
    }

    /*******************************************************************************************************************/

    /**
     * 构造前端支付签名
     *
     * @param appId      小程序id
     * @param timestamp  时间戳
     * @param nonceStr   随机字符串
     * @param packageStr
     * @param filename   文件目录+文件名
     * @return
     * @throws Exception
     */
    public static String getPaySign(String appId, long timestamp, String nonceStr, String packageStr
            , String filename) throws Exception {
        //构造签名串
        String message = buildPaySign(appId, timestamp, nonceStr, packageStr);
        //String私钥转私钥PrivateKey
        PrivateKey privateKey1 = getPrivateKey(filename);
        //对私钥进行签名
        return sign(message.getBytes(StandardCharsets.UTF_8), privateKey1);
    }

    private static String buildPaySign(String appId, long timestamp, String nonceStr, String packageStr) {
        return Stream.of(appId, String.valueOf(timestamp), nonceStr, packageStr)
                .collect(Collectors.joining("\n", "", "\n"));
    }

    /*******************************************************************************************************************/

    /**
     * 支付下单返回的签名验证
     *
     * @param wxPayCertificate   微信平台证书对象
     * @param wechatpaySignature 微信待验证签名
     * @param wechatpayTimestamp 响应时间戳
     * @param wechatpayNonce     响应随机数
     * @param responseBody       响应体
     * @return 是否验证成功
     */
    static boolean doVerifySignature(Certificate wxPayCertificate, String wechatpaySignature, String wechatpayTimestamp, String wechatpayNonce
            , String responseBody) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        //构造验签名串
        String responseSigntureStr = buildResponseSignatureStr(wechatpayTimestamp, wechatpayNonce, responseBody);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initVerify(wxPayCertificate);
        signer.update(responseSigntureStr.getBytes(StandardCharsets.UTF_8));
        return signer.verify(Base64Utils.decodeFromString(wechatpaySignature));
    }

    /**
     * 获取证书对象(公钥pem)
     *
     * @param filename 文件路径  (required)
     * @return 证书对象(pem)
     */
    public static X509Certificate getCertificate(String filename) {
        log.trace("*****************do getCertificate********************");
        try {
            final CertificateFactory cf = CertificateFactory.getInstance("X509");
            //InputStream is = new FileInputStream(new File(filename));
            InputStream is = Files.newInputStream(Paths.get(filename), StandardOpenOption.READ);
            log.trace("getCertificate 执行完毕");
            return (X509Certificate) cf.generateCertificate(is);
        } catch (CertificateExpiredException e) {
            throw new RuntimeException("证书已过期", e);
        } catch (CertificateNotYetValidException e) {
            throw new RuntimeException("证书尚未生效", e);
        } catch (CertificateException e) {
            throw new RuntimeException("无效的证书", e);
        } catch (IOException e) {
            throw new RuntimeException("读取不到证书", e);
        }
    }

    /**
     * 构造验签名串
     *
     * @param wechatpayTimestamp 响应时间戳
     * @param wecahtpayNonce     响应随机数
     * @param responseBody       响应体
     * @return 签名串
     */
    private static String buildResponseSignatureStr(String wechatpayTimestamp, String wecahtpayNonce
            , String responseBody) {
        return Stream.of(wechatpayTimestamp, wecahtpayNonce, responseBody)
                .collect(Collectors.joining("\n", "", "\n"));
    }

    /**
     * 用微信V3密钥解密响应体.
     *
     * @param apiV3Key       API V3 KEY  API v3密钥 商户平台设置的32位字符串
     * @param associatedData response.body.data[i].encrypt_certificate.associated_data
     * @param nonce          response.body.data[i].encrypt_certificate.nonce
     * @param ciphertext     response.body.data[i].encrypt_certificate.ciphertext
     * @return the string
     * @throws GeneralSecurityException the general security exception
     */
    public static String decryptResponseBody(String apiV3Key, String associatedData, String nonce, String ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            SecretKeySpec key = new SecretKeySpec(apiV3Key.getBytes(StandardCharsets.UTF_8), "AES");
            GCMParameterSpec spec = new GCMParameterSpec(128, nonce.getBytes(StandardCharsets.UTF_8));

            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            cipher.updateAAD(associatedData.getBytes(StandardCharsets.UTF_8));

            byte[] bytes;
            try {
                bytes = cipher.doFinal(Base64Utils.decodeFromString(ciphertext));
            } catch (GeneralSecurityException e) {
                throw new IllegalArgumentException(e);
            }
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException(e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(e);
        }
    }

}

```

```java
package com.yanbo.springboot.commons.utils.wxpay.apiv3;

import com.yanbo.springboot.commons.pojo.wxpay.apiv3.WxPayNotify;
import com.yanbo.springboot.commons.utils.JacksonUtils;
import lombok.extern.slf4j.Slf4j;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

/**
 * @author ChihoiTse
 * @jdk 8
 * @description:
 * @date 2020/12/31 0031 - 15:32
 */
@Slf4j
@SuppressWarnings("unused")
public class WxPayApiV3NotifyUtils {

    /**
     * 回调的验证签名
     * 支付下单返回的签名验证@see{com.yanbo.sellfood.portalweb.controller.WxPayController#doValidated(org.apache.http.client.methods.CloseableHttpResponse)}
     *
     * @param requestJsonBody  请求体json
     * @param wxPayCertificate 微信平台证书对象
     * @param request
     * @return
     * @throws Exception
     */
    private static boolean verify(String requestJsonBody, Certificate wxPayCertificate, HttpServletRequest request)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        //微信验签字段
        log.trace("requestBody is : " + requestJsonBody);
        String wechatpaySignature = request.getHeader("wechatpay-signature");
        log.trace("wechatpay-signature: " + wechatpaySignature);
        String wechatpayTimestamp = request.getHeader("wechatpay-timestamp");
        log.trace("wechatpay-timestamp: " + wechatpayTimestamp);
        String wechatpayNonce = request.getHeader("wechatpay-nonce");
        log.trace("wechatpay-nonce: " + wechatpayTimestamp);
        //微信验签
        boolean isVerify = WxPayApiV3Utils.doVerifySignature(wxPayCertificate, wechatpaySignature, wechatpayTimestamp
                , wechatpayNonce, requestJsonBody);
        log.trace("isVerify : " + isVerify);
        return isVerify;
    }

    public static boolean verify(Map<String, Object> map, Certificate wxPayCertificate, HttpServletRequest request) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        //微信验签字段
        String requestJsonBody = JacksonUtils.objectToJson(map);
        return verify(requestJsonBody, wxPayCertificate, request);
    }

    public static boolean verify(WxPayNotify payNotify, Certificate wxPayCertificate, HttpServletRequest request) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        //微信验签字段
        String requestJsonBody = JacksonUtils.objectToJson(payNotify);
        return verify(requestJsonBody, wxPayCertificate, request);
    }

    /**
     * 回调时自动更新微信平台证书 惰性加载
     *
     * @param request
     * @param wechatpaySerial 微信平台序列号
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeySpecException
     * @throws SignatureException
     * @throws InvalidKeyException
     */
    public static void autoupdateCertificate(HttpServletRequest request, String wechatpaySerial) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        //如果没有平台证书或者证书序列号不匹配，则获取平台证书
        WxPayApiV3Utils.downloadCertificateAndiDecrypt(request, wechatpaySerial);
    }

}

```

```java
package com.yanbo.springboot.commons.utils.wxpay.apiv3;

import java.security.cert.Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author ChihoiTse
 * @jdk 8
 * @description:
 * @date 2021/2/2 0002 - 18:51
 */
public class WxPayApiV3Contants {
    /**
     * 小程序id
     */
    public static final String APPID = "";

    /**
     * 小程序秘钥
     */
    public static final String SECRET = "";

    /**
     * 商户号
     */
    public static final String mchid = "";

    /**
     * APIv3商户证书序列号
     */
    public static final String APIV3_SERIAL_NO = "";

    /**
     * APIv3商户证书所处目录和名字
     */
    public static final String APIV3_PUBLICKEY_FILENAME = "resource/cert/merchant/apiclient_key.pem";

    /**
     * APIv3的32位解密秘钥
     */
    public static final String APIV3_KEY = "";

    /**
     * 微信支付下单API
     */
    public static final String PLACE_AN_ORDER_URL = "https://api.mch.weixin.qq.com/v3/pay/transactions/jsapi";

    /**
     * 获取微信平台证书API
     */
    public static final String CERTIFICATES_URL = "https://api.mch.weixin.qq.com/v3/certificates";

    /**
     * 回调API
     */
    public static final String CALLBACK_URL = "";

    /**
     * 线程安全证书map
     */
    public static final Map<String, Certificate> CERTIFICATE_MAP = new ConcurrentHashMap<>();
}

```

### 对应bo

```java
package com.yanbo.springboot.commons.pojo.wxpay.apiv3;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.io.Serializable;

/**
 * 微信支付回调解密后请求体资源
 *
 * @author ChihoiTse
 * @jdk 8
 * @description:
 * @date 2020/12/30 0030 - 15:34
 */
@Data
@SuperBuilder
@AllArgsConstructor
@NoArgsConstructor
public class WxPayNotifyResource implements Serializable {

    private static final long serialVersionUID = 8831064089654169530L;

    private String mchid;

    private String appid;

    private String out_trade_no;

    private String transaction_id;

    private String trade_type;

    private String trade_state;

    private String trade_state_desc;

    private String bank_type;

    private String attach;

    private String success_time;

    private Payer payer;

    private Amount amount;

    @SuppressWarnings({"WeakerAccess", "InnerClassMayBeStatic"})
    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public class Payer implements Serializable{
        private static final long serialVersionUID = -3409512313665586106L;
        private String openid;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    @SuppressWarnings({"WeakerAccess", "InnerClassMayBeStatic"})
    public class Amount implements Serializable{
        private static final long serialVersionUID = 6348669793534247157L;
        private Integer total;

        private Integer payer_total;

        private String currency;

        private String payer_currency;
    }

}


```

```java
package com.yanbo.springboot.commons.pojo.wxpay.apiv3;

import lombok.*;

import java.io.Serializable;

/**
 * 接收微信支付通知VO
 *
 * @author ChihoiTse
 * @jdk 8
 * @description:
 * @date 2020/12/30 0030 - 12:23
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WxPayNotify implements Serializable {

    private static final long serialVersionUID = -5789740355011164571L;
    /**
     * 通知的唯一ID
     */
    private String id;

    /**
     * 通知创建时间
     */
    private String create_time;

    /**
     * 通知类型 支付成功通知的类型为TRANSACTION.SUCCESS
     */
    private String event_type;

    /**
     * 通知数据类型 支付成功通知为encrypt-resource
     */
    private String resource_type;

    /**
     * 通知资源数据
     */
    private Resource resource;

    /**
     * 回调摘要
     */
    private String summary;

    /**
     * 通知资源数据
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @SuppressWarnings({"WeakerAccess", "InnerClassMayBeStatic"})
    public class Resource implements Serializable{
        private static final long serialVersionUID = 1702670080302378565L;
        /**
         * 原始类型
         */
        private String original_type;

        /**
         * 加密算法类型
         */
        private String algorithm;

        /**
         * 数据密文
         */
        private String ciphertext;

        /**
         * 附加数据
         */
        private String associated_data;

        /**
         * 随机串
         */
        private String nonce;
    }

}

```

```java
package com.yanbo.springboot.commons.pojo.wxpay.apiv3;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.io.Serializable;
import java.util.List;

/**
 * 获取证书时资源
 *
 * @author ChihoiTse
 * @jdk 8
 * @date 2021/1/29 0029 - 15:52
 */
@Data
@SuperBuilder
@AllArgsConstructor
@NoArgsConstructor
public class WxCertificatesResource implements Serializable {

    private static final long serialVersionUID = 8403881209233250022L;

    private List<WxCertificateData> data;

    @SuppressWarnings({"WeakerAccess", "InnerClassMayBeStatic"})
    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class WxCertificateData implements Serializable {

        private static final long serialVersionUID = -6860082313627835046L;

        private String serial_no;

        private String effective_time;

        private String expire_time;

        private EncryptCertificate encrypt_certificate;
    }

    @SuppressWarnings({"WeakerAccess", "InnerClassMayBeStatic"})
    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class EncryptCertificate implements Serializable {

        private static final long serialVersionUID = 4190133620252667780L;

        private String algorithm;

        private String nonce;

        private String associated_data;

        private String ciphertext;
    }
}

```







# 相关算法

## 后端签名生成算法

>[签名生成 - WechatPay-API-v3 (gitbook.io)](https://wechatpay-api.gitbook.io/wechatpay-api-v3/qian-ming-zhi-nan-1/qian-ming-sheng-cheng)

商户可以按照下述步骤生成请求的签名。在本节的最后，我们准备了多种常用编程语言的演示代码供开发者参考。

微信支付API v3要求商户对请求进行签名。微信支付会在收到请求后进行签名的验证。如果签名验证不通过，微信支付API v3将会拒绝处理请求，并返回`401 Unauthorized`。

### **准备**

商户需要拥有一个微信支付商户号，并通过超级管理员账号登陆商户平台，获取[商户API证书](https://wechatpay-api.gitbook.io/wechatpay-api-v3/ren-zheng/zheng-shu#shang-hu-api-zheng-shu)。商户API证书的压缩包中包含了签名必需的私钥和商户证书。

### **构造签名串**

我们希望商户的技术开发人员按照当前文档约定的规则构造签名串。微信支付会使用同样的方式构造签名串。如果商户构造签名串的方式错误，将导致签名验证不通过。下面先说明签名串的具体格式。

签名串一共有五行，每一行为一个参数。行尾以`\n`（换行符，ASCII编码值为0x0A）结束，包括最后一行。如果参数本身以`\n`结束，也需要附加一个`\n`。



```
HTTP请求方法\n
URL\n
请求时间戳\n
请求随机串\n
请求报文主体\n
```

我们通过在命令行中调用"获取微信支付平台证书"接口，一步一步向开发者介绍如何进行请求签名。按照接口文档，获取商户平台证书的URL为`https://api.mch.weixin.qq.com/v3/certificates`，请求方法为`GET`，没有查询参数。

第一步，获取HTTP请求的方法（`GET`,`POST`,`PUT`等）



```
GET
```

第二步，获取请求的绝对URL，并去除域名部分得到参与签名的URL。如果请求中有查询参数，URL末尾应附加有'?'和对应的查询字符串。



```
/v3/certificates
```

第三步，获取发起请求时的系统当前时间戳，即格林威治时间1970年01月01日00时00分00秒(北京时间1970年01月01日08时00分00秒)起至现在的总秒数，作为请求时间戳。微信支付会拒绝处理很久之前发起的请求，请商户保持自身系统的时间准确。



```
$ date +%s
1554208460
```

第四步，生成一个请求随机串，可参见[生成随机数算法](https://pay.weixin.qq.com/wiki/doc/api/micropay.php?chapter=4_3)。这里，我们使用命令行直接生成一个。



```
$ hexdump -n 16 -e '4/4 "%08X" 1 "\n"' /dev/random
593BEC0C930BF1AFEB40B4A08C8FB242
```

第五步，获取请求中的请求报文主体（request body）。

- 请求方法为`GET`时，报文主体为空。
- 当请求方法为`POST`或`PUT`时，请使用**真实发送**的`JSON`报文。
- 图片上传API，请使用`meta`对应的`JSON`报文。

对于下载证书的接口来说，请求报文主体是一个空串。

第六步，按照前述规则，构造的请求签名串为：



```
GET\n
/v3/certificates\n
1554208460\n
593BEC0C930BF1AFEB40B4A08C8FB242\n
\n
```

### **计算签名值**

绝大多数编程语言提供的签名函数支持对**签名数据**进行签名。强烈建议商户调用该类函数，使用商户私钥对**待签名串**进行SHA256 with RSA签名，并对签名结果进行**Base64编码**得到签名值。

下面我们使用命令行演示如何生成签名。



```
$ echo -n -e \
  "GET\n/v3/certificates\n1554208460\n593BEC0C930BF1AFEB40B4A08C8FB242\n\n" \
  | openssl dgst -sha256 -sign apiclient_key.pem \
  | openssl base64 -A
uOVRnA4qG/MNnYzdQxJanN+zU+lTgIcnU9BxGw5dKjK+VdEUz2FeIoC+D5sB/LN+nGzX3hfZg6r5wT1pl2ZobmIc6p0ldN7J6yDgUzbX8Uk3sD4a4eZVPTBvqNDoUqcYMlZ9uuDdCvNv4TM3c1WzsXUrExwVkI1XO5jCNbgDJ25nkT/c1gIFvqoogl7MdSFGc4W4xZsqCItnqbypR3RuGIlR9h9vlRsy7zJR9PBI83X8alLDIfR1ukt1P7tMnmogZ0cuDY8cZsd8ZlCgLadmvej58SLsIkVxFJ8XyUgx9FmutKSYTmYtWBZ0+tNvfGmbXU7cob8H/4nLBiCwIUFluw==
```

### **设置HTTP头**

微信支付商户API v3要求请求通过HTTP`Authorization`头来传递签名。`Authorization`由**认证类型**和**签名信息**两个部分组成。

```
Authorization: 认证类型 签名信息
```

具体组成为：

1. 认证类型，目前为`WECHATPAY2-SHA256-RSA2048`

2. 签名信息

   - 发起请求的商户（包括直连商户、服务商或渠道商）的商户号`mchid`
   - [商户API证书](https://wechatpay-api.gitbook.io/wechatpay-api-v3/ren-zheng/zheng-shu#shang-hu-api-zheng-shu)序列号`serial_no`，用于[声明所使用的证书](https://wechatpay-api.gitbook.io/wechatpay-api-v3/ren-zheng/zheng-shu#sheng-ming-suo-shi-yong-de-zheng-shu)
   - 请求随机串`nonce_str`
   - 时间戳`timestamp`
   - 签名值`signature`

   注：以上五项签名信息，无顺序要求。

`Authorization`头的示例如下：（注意，示例因为排版可能存在换行，实际数据应在一行）

```
Authorization: WECHATPAY2-SHA256-RSA2048 mchid="1900009191",nonce_str="593BEC0C930BF1AFEB40B4A08C8FB242",signature="uOVRnA4qG/MNnYzdQxJanN+zU+lTgIcnU9BxGw5dKjK+VdEUz2FeIoC+D5sB/LN+nGzX3hfZg6r5wT1pl2ZobmIc6p0ldN7J6yDgUzbX8Uk3sD4a4eZVPTBvqNDoUqcYMlZ9uuDdCvNv4TM3c1WzsXUrExwVkI1XO5jCNbgDJ25nkT/c1gIFvqoogl7MdSFGc4W4xZsqCItnqbypR3RuGIlR9h9vlRsy7zJR9PBI83X8alLDIfR1ukt1P7tMnmogZ0cuDY8cZsd8ZlCgLadmvej58SLsIkVxFJ8XyUgx9FmutKSYTmYtWBZ0+tNvfGmbXU7cob8H/4nLBiCwIUFluw==",timestamp="1554208460",serial_no="1DDE55AD98ED71D6EDD4A4A16996DE7B47773A8C"
```

最终我们可以组一个包含了签名的HTTP请求了。

```
$ curl https://api.mch.weixin.qq.com/v3/certificates -H 'Authorization: WECHATPAY2-SHA256-RSA2048 mchid="1900009191",nonce_str="593BEC0C930BF1AFEB40B4A08C8FB242",signature="uOVRnA4qG/MNnYzdQxJanN+zU+lTgIcnU9BxGw5dKjK+VdEUz2FeIoC+D5sB/LN+nGzX3hfZg6r5wT1pl2ZobmIc6p0ldN7J6yDgUzbX8Uk3sD4a4eZVPTBvqNDoUqcYMlZ9uuDdCvNv4TM3c1WzsXUrExwVkI1XO5jCNbgDJ25nkT/c1gIFvqoogl7MdSFGc4W4xZsqCItnqbypR3RuGIlR9h9vlRsy7zJR9PBI83X8alLDIfR1ukt1P7tMnmogZ0cuDY8cZsd8ZlCgLadmvej58SLsIkVxFJ8XyUgx9FmutKSYTmYtWBZ0+tNvfGmbXU7cob8H/4nLBiCwIUFluw==",timestamp="1554208460",serial_no="1DDE55AD98ED71D6EDD4A4A16996DE7B47773A8C"'
```

### **演示代码**

开发者可以查看[开发工具](https://wechatpay-api.gitbook.io/wechatpay-api-v3/kai-fa-gong-ju)相关章节，获取对应语言的库。如何在程序中加载私钥，请参考[常见问题](https://wechatpay-api.gitbook.io/wechatpay-api-v3/chang-jian-wen-ti/qian-ming-xiang-guan#ru-he-zai-cheng-xu-zhong-jia-zai-si-yao)。

计算签名的示例代码如下。

```
import okhttp3.HttpUrl;
import java.security.Signature;
import java.util.Base64;

// Authorization: <schema> <token>
// GET - getToken("GET", httpurl, "")
// POST - getToken("POST", httpurl, json)
String schema = "WECHATPAY2-SHA256-RSA2048";
HttpUrl httpurl = HttpUrl.parse(url);

String getToken(String method, HttpUrl url, String body) {
    String nonceStr = "your nonce string";
    long timestamp = System.currentTimeMillis() / 1000;
    String message = buildMessage(method, url, timestamp, nonceStr, body);
    String signature = sign(message.getBytes("utf-8"));

    return "mchid=\"" + yourMerchantId + "\","
    + "nonce_str=\"" + nonceStr + "\","
    + "timestamp=\"" + timestamp + "\","
    + "serial_no=\"" + yourCertificateSerialNo + "\","
    + "signature=\"" + signature + "\"";
}

String sign(byte[] message) {
    Signature sign = Signature.getInstance("SHA256withRSA");
    sign.initSign(yourPrivateKey);
    sign.update(message);

    return Base64.getEncoder().encodeToString(sign.sign());
}

String buildMessage(String method, HttpUrl url, long timestamp, String nonceStr, String body) {
    String canonicalUrl = url.encodedPath();
    if (url.encodedQuery() != null) {
      canonicalUrl += "?" + url.encodedQuery();
    }

    return method + "\n"
        + canonicalUrl + "\n"
        + timestamp + "\n"
        + nonceStr + "\n"
        + body + "\n";
}
```



---



## 签名验证



商户可以按照下述步骤验证应答或者回调的签名。

如果验证商户的请求签名正确，微信支付会在应答的HTTP头部中包括应答签名。我们建议商户验证应答签名。

同样的，微信支付会在回调的HTTP头部中包括回调报文的签名。商户**必须**验证回调的签名，以确保回调是由微信支付发送。

### **获取平台证书**

微信支付API v3使用**微信支付**的平台私钥（不是**商户私钥**）进行应答签名。相应的，商户的技术人员应使用微信支付平台证书中的公钥验签。目前平台证书只提供API进行下载，请参考[获取平台证书列表](https://wechatpay-api.gitbook.io/wechatpay-api-v3/jie-kou-wen-dang/ping-tai-zheng-shu#huo-qu-ping-tai-zheng-shu-lie-biao)。



再次提醒，应答和回调的签名验证使用的是[微信支付平台证书](https://wechatpay-api.gitbook.io/wechatpay-api-v3/jie-kou-wen-dang/ping-tai-zheng-shu)，不是商户API证书。使用商户API证书是验证不过的。

### **检查平台证书序列号**

微信支付的平台证书序列号位于HTTP头`Wechatpay-Serial`。验证签名前，请商户先检查序列号是否跟商户当前所持有的**微信支付平台证书**的序列号一致。如果不一致，请重新获取证书。否则，签名的私钥和证书不匹配，将无法成功验证签名。

### **构造验签名串**

首先，商户先从应答中获取以下信息。

- HTTP头`Wechatpay-Timestamp`中的应答时间戳。
- HTTP头`Wechatpay-Nonce`中的应答随机串
- 应答主体（response Body）

然后，请按照以下规则构造应答的验签名串。签名串共有三行，行尾以`\n`结束，包括最后一行。`\n`为换行符（ASCII编码值为0x0A）。若应答报文主体为空（如HTTP状态码为`204 No Content`），最后一行仅为一个`\n`换行符。



```
应答时间戳\n
应答随机串\n
应答报文主体\n
```

如某个应答的HTTP报文为（省略了ciphertext的具体内容）：



```
HTTP/1.1 200 OK
Server: nginx
Date: Tue, 02 Apr 2019 12:59:40 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 2204
Connection: keep-alive
Keep-Alive: timeout=8
Content-Language: zh-CN
Request-ID: e2762b10-b6b9-5108-a42c-16fe2422fc8a
Wechatpay-Nonce: c5ac7061fccab6bf3e254dcf98995b8c
Wechatpay-Signature: CtcbzwtQjN8rnOXItEBJ5aQFSnIXESeV28Pr2YEmf9wsDQ8Nx25ytW6FXBCAFdrr0mgqngX3AD9gNzjnNHzSGTPBSsaEkIfhPF4b8YRRTpny88tNLyprXA0GU5ID3DkZHpjFkX1hAp/D0fva2GKjGRLtvYbtUk/OLYqFuzbjt3yOBzJSKQqJsvbXILffgAmX4pKql+Ln+6UPvSCeKwznvtPaEx+9nMBmKu7Wpbqm/+2ksc0XwjD+xlvlECkCxfD/OJ4gN3IurE0fpjxIkvHDiinQmk51BI7zQD8k1znU7r/spPqB+vZjc5ep6DC5wZUpFu5vJ8MoNKjCu8wnzyCFdA==
Wechatpay-Timestamp: 1554209980
Wechatpay-Serial: 5157F09EFDC096DE15EBE81A47057A7232F1B8E1
Cache-Control: no-cache, must-revalidate

{"data":[{"serial_no":"5157F09EFDC096DE15EBE81A47057A7232F1B8E1","effective_time":"2018-03-26T11:39:50+08:00","expire_time":"2023-03-25T11:39:50+08:00","encrypt_certificate":{"algorithm":"AEAD_AES_256_GCM","nonce":"4de73afd28b6","associated_data":"certificate","ciphertext":"..."}}]}
```

则验签名串为



```
1554209980
c5ac7061fccab6bf3e254dcf98995b8c
{"data":[{"serial_no":"5157F09EFDC096DE15EBE81A47057A7232F1B8E1","effective_time":"2018-03-26T11:39:50+08:00","expire_time":"2023-03-25T11:39:50+08:00","encrypt_certificate":{"algorithm":"AEAD_AES_256_GCM","nonce":"4de73afd28b6","associated_data":"certificate","ciphertext":"..."}}]}
```

### **获取应答签名**

微信支付的应答签名通过HTTP头`Wechatpay-Signature`传递。（注意，示例因为排版可能存在换行，实际数据应在一行）



```
Wechatpay-Signature: CtcbzwtQjN8rnOXItEBJ5aQFSnIXESeV28Pr2YEmf9wsDQ8Nx25ytW6FXBCAFdrr0mgqngX3AD9gNzjnNHzSGTPBSsaEkIfhPF4b8YRRTpny88tNLyprXA0GU5ID3DkZHpjFkX1hAp/D0fva2GKjGRLtvYbtUk/OLYqFuzbjt3yOBzJSKQqJsvbXILffgAmX4pKql+Ln+6UPvSCeKwznvtPaEx+9nMBmKu7Wpbqm/+2ksc0XwjD+xlvlECkCxfD/OJ4gN3IurE0fpjxIkvHDiinQmk51BI7zQD8k1znU7r/spPqB+vZjc5ep6DC5wZUpFu5vJ8MoNKjCu8wnzyCFdA==
```

对`Wechatpay-Signature`的字段值使用**Base64**进行解码，得到应答签名。



某些代理服务器或CDN服务提供商，转发时会“过滤“微信支付扩展的HTTP头，导致应用层无法取到微信支付的签名信息。商户遇到这种情况时，我们建议尝试调整代理服务器配置，或者通过直连的方式访问微信支付的服务器和接收通知。

### **验证签名**

很多编程语言的签名验证函数支持对**验签名串和签名**进行签名验证。强烈建议商户调用该类函数，使用微信支付平台公钥对**验签名串和签名**进行SHA256 with RSA签名验证。

下面展示使用命令行演示如何进行验签。假设我们已经获取了平台证书并保存为`1900009191_wxp_cert.pem`。

首先，从微信支付平台证书导出微信支付平台公钥



```
$ openssl x509 -in 1900009191_wxp_cert.pem -pubkey -noout > 1900009191_wxp_pub.pem
$ cat 1900009191_wxp_pub.pem
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4zej1cqugGQtVSY2Ah8R
MCKcr2UpZ8Npo+5Ja9xpFPYkWHaF1Gjrn3d5kcwAFuHHcfdc3yxDYx6+9grvJnCA
2zQzWjzVRa3BJ5LTMj6yqvhEmtvjO9D1xbFTA2m3kyjxlaIar/RYHZSslT4VmjIa
tW9KJCDKkwpM6x/RIWL8wwfFwgz2q3Zcrff1y72nB8p8P12ndH7GSLoY6d2Tv0OB
2+We2Kyy2+QzfGXOmLp7UK/pFQjJjzhSf9jxaWJXYKIBxpGlddbRZj9PqvFPTiep
8rvfKGNZF9Q6QaMYTpTp/uKQ3YvpDlyeQlYe4rRFauH3mOE6j56QlYQWivknDX9V
rwIDAQAB
-----END PUBLIC KEY-----
```



Java支持使用证书初始化签名对象，详见[`initVerify(Certificate)`](https://docs.oracle.com/javase/8/docs/api/java/security/Signature.html#initVerify-java.security.cert.Certificate-)，并不需要先导出公钥。

然后，把签名base64解码后保存为文件`signature.txt`



```
$ openssl base64 -d -A <<< \ 'CtcbzwtQjN8rnOXItEBJ5aQFSnIXESeV28Pr2YEmf9wsDQ8Nx25ytW6FXBCAFdrr0mgqngX3AD9gNzjnNHzSGTPBSsaEkIfhPF4b8YRRTpny88tNLyprXA0GU5ID3DkZHpjFkX1hAp/D0fva2GKjGRLtvYbtUk/OLYqFuzbjt3yOBzJSKQqJsvbXILffgAmX4pKql+Ln+6UPvSCeKwznvtPaEx+9nMBmKu7Wpbqm/+2ksc0XwjD+xlvlECkCxfD/OJ4gN3IurE0fpjxIkvHDiinQmk51BI7zQD8k1znU7r/spPqB+vZjc5ep6DC5wZUpFu5vJ8MoNKjCu8wnzyCFdA==' > signature.txt
```

最后，验证签名



```
$ openssl dgst -sha256 -verify 1900009191_wxp_pub.pem -signature signature.txt << EOF
1554209980
c5ac7061fccab6bf3e254dcf98995b8c
{"data":[{"serial_no":"5157F09EFDC096DE15EBE81A47057A7232F1B8E1","effective_time":"2018-03-26T11:39:50+08:00","expire_time":"2023-03-25T11:39:50+08:00","encrypt_certificate":{"algorithm":"AEAD_AES_256_GCM","nonce":"d215b0511e9c","associated_data":"certificate","ciphertext":"..."}}]}
EOF
Verified OK
```

[
  ](https://wechatpay-api.gitbook.io/wechatpay-api-v3/qian-ming-zhi-nan-1/qian-ming-sheng-cheng)

---

## 证书和回调报文解密



为了保证安全性，微信支付在回调通知和平台证书下载接口中，对关键信息进行了AES-256-GCM加密。本章节详细介绍了加密报文的格式，以及如何进行解密。

### **加密报文格式**

`AES-GCM`是一种NIST标准的[认证加密](https://zh.wikipedia.org/wiki/认证加密)算法， 是一种能够同时保证数据的保密性、 完整性和真实性的一种加密模式。它最广泛的应用是在TLS中。

证书和回调报文使用的加密密钥为[APIv3密钥](https://wechatpay-api.gitbook.io/wechatpay-api-v3/ren-zheng/api-v3-mi-yao)。

对于加密的数据，我们使用了一个独立的JSON对象来表示。为了方便阅读，示例做了Pretty格式化，并加入了注释。



```
{
        "original_type": "transaction", // 加密前的对象类型
        "algorithm":"AEAD_AES_256_GCM", // 加密算法
        
        // Base64编码后的密文
        "ciphertext": "...", 
        // 加密使用的随机串初始化向量）
        "nonce": "...", 
        // 附加数据包（可能为空）
        "associated_data": "" 
}
```



 加密的随机串，跟签名时使用的随机串没有任何关系，是不一样的。

### **解密**

算法接口的细节，可以参考[RFC 5116](https://tools.ietf.org/html/rfc5116)。

大部分编程语言（较新版本）都支持了`AEAD_AES_256_GCM`。开发者可以参考下列的示例，了解如何使用您的编程语言实现解密。

Java

```
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesUtil {

  static final int KEY_LENGTH_BYTE = 32;
  static final int TAG_LENGTH_BIT = 128;
  private final byte[] aesKey;

  public AesUtil(byte[] key) {
    if (key.length != KEY_LENGTH_BYTE) {
      throw new IllegalArgumentException("无效的ApiV3Key，长度必须为32个字节");
    }
    this.aesKey = key;
  }

  public String decryptToString(byte[] associatedData, byte[] nonce, String ciphertext)
      throws GeneralSecurityException, IOException {
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

      SecretKeySpec key = new SecretKeySpec(aesKey, "AES");
      GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, nonce);

      cipher.init(Cipher.DECRYPT_MODE, key, spec);
      cipher.updateAAD(associatedData);

      return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)), "utf-8");
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new IllegalStateException(e);
    } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
      throw new IllegalArgumentException(e);
    }
  }
}
```

[
  ](https://wechatpay-api.gitbook.io/wechatpay-api-v3/qian-ming-zhi-nan-1/qian-ming-yan-zheng)

---

## 前端签名生成算法

### 小程序调起支付的参数需要按照签名规则进行签名计算：

#### 1、构造签名串

```
签名串一共有四行，每一行为一个参数。行尾以\n（换行符，ASCII编码值为0x0A）结束，包括最后一行。
如果参数本身以\n结束，也需要附加一个\n
```



**参与签名字段及格式：**

```
公众号id
时间戳
随机字符串
订单详情扩展字符串
```



**数据举例：**

```
wx8888888888888888
1414561699
5K8264ILTKCH16CQ2502SI8ZNMTM67VS
prepay_id=wx201410272009395522657a690389285100 
```



#### 2、计算签名值

计算签名值可参考：[签名生成](https://wechatpay-api.gitbook.io/wechatpay-api-v3/qian-ming-zhi-nan-1/qian-ming-sheng-cheng#ji-suan-qian-ming-zhi)



signType参数不参与签名，但需要传递，默认值为“RSA”，生成的签名需要通过字段paySign传递。

### 调用wx.requestPayment(OBJECT)发起微信支付

Object参数说明：

| 参数名             | 变量      | 类型[长度限制] | 必填 | 描述                                                         |
| :----------------- | :-------- | :------------- | :--- | :----------------------------------------------------------- |
| 时间戳             | timeStamp | string[1,32]   | 是   | 当前的时间，其他详见[时间戳规则](https://pay.weixin.qq.com/wiki/doc/api/jsapi.php?chapter=4_2)。 示例值：1414561699 |
| 随机字符串         | nonceStr  | string[1,32]   | 是   | 随机字符串，不长于32位。推荐[随机数生成算法](https://pay.weixin.qq.com/wiki/doc/api/jsapi.php?chapter=4_3)。 示例值：5K8264ILTKCH16CQ2502SI8ZNMTM67VS |
| 订单详情扩展字符串 | package   | string[1,128]  | 是   | 统一下单接口返回的prepay_id参数值，提交格式如：prepay_id=*** 示例值：prepay_id=wx201410272009395522657a690389285100 |
| 签名方式           | signType  | string[1,32]   | 是   | 签名类型，默认为RSA，仅支持RSA。 示例值：RSA                 |
| 签名               | paySign   | string[1,64]   | 是   | 签名，使用字段appId、timeStamp、nonceStr、package按照[签名生成算法](https://wechatpay-api.gitbook.io/wechatpay-api-v3/qian-ming-zhi-nan-1/qian-ming-sheng-cheng)计算得出的签名值 示例值：oR9d8PuhnIc+YZ8cBHFCwfgpaK9gd7vaRvkYD7rthRAZ\/X+QBhcCYL21N7cHCTUxbQ+EAt6Uy+lwSN22f5YZvI45MLko8Pfso0jm46v5hqcVwrk6uddkGuT+Cdvu4WBqDzaDjnNa5UK3GfE1Wfl2gHxIIY5lLdUgWFts17D4WuolLLkiFZV+JSHMvH7eaLdT9N5GBovBwu5yYKUR7skR8Fu+LozcSqQixnlEZUfyE55feLOQTUYzLmR9pNtPbPsu6WVhbNHMS3Ss2+AehHvz+n64GDmXxbX++IOBvm2olHu3PsOUGRwhudhVf7UcGcunXt8cqNjKNqZLhLw4jq\/xDg== |

#### 回调结果

| 回调类型[长度限制] | errMsg                               | 类型[长度限制]                                             |
| :----------------- | :----------------------------------- | :--------------------------------------------------------- |
| success            | requestPayment:ok                    | 调用支付成功                                               |
| fail               | requestPayment:fail cancel           | 用户取消支付                                               |
| fail               | requestPayment:fail (detail message) | 调用支付失败，其中 detail message 为后台返回的详细失败原因 |



## 