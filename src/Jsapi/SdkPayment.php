<?php
namespace Entere\Wxpay\Jsapi;

class SdkPayment
{
	public $data = null;
	private $appid;
	private $appsecret;
	private $curl_proxy_host = '0.0.0.0';
	private $curl_proxy_port = 0;
	private $report_levenl = 0;
	private $key;
	private $mchid;
	private $sslcert_path;
	private $sslkey_path;
	private $notify_url;
	private $prepay_id;
	private $log;
	protected $values = array();
	protected $values_js = array();
	protected $values_re = array();
	
	//设置config
	public function setAppidConf($appid)
	{
		$this->appid = $appid;
		return $this;
	}
	
	public function setMchidConf($mchid)
	{
		$this->mchid = $mchid;
		return $this;
	}
	
	public function setAppsecret($appsecret)
	{
		$this->appsecret = $appsecret;
		return $this;
	}
	
	public function setKey($key)
	{
		$this->key = $key;
		return $this;
	}
	
	public function setSslcertPath($sslcert_path)
	{
		$this->sslcert_path = $sslcert_path;
		return $this;
	}
	
	public function setSslkeyPath($sslkey_path)
	{
		$this->sslkey_path = $sslkey_path;
		return $this;
	}
	
	public function setCurlProxyHost($curl_proxy_host)
	{
		$this->curl_proxy_host = $curl_proxy_host;
		return $this;
	}
	
	public function setCurlProxyPort($curl_proxy_port)
	{
		$this->curl_proxy_port = $curl_proxy_port;
		return $this;
	}
	
	public function setNotifyUrlConf($notify_url)
	{
		$this->notify_url = $notify_url;
		return $this;
	}
	
	/**
	 * 获取用户的openid
	 * @return 用户的openid
	 */
	public function getOpenid()
	{
		//通过code获得openid
		if (!isset($_GET['code'])) {
			//触发微信返回code码
			$base_url = urlencode('http://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'] . $_SERVER['QUERY_STRING']);
			$baseurl = rtrim($base_url, "%2F");
			$url = $this->__createOauthUrlForCode($baseurl);
			Header("Location: $url");
			exit();
		} else {
			//获取code码，以获取openid
			$code = $_GET['code'];
			$openid = $this->getOpenidFromMp($code);
			return $openid;
		}
	}
	
	/**
	 * 构造获取code的url连接
	 * @param string $redirect_url 微信服务器回跳的url，需要url编码
	 * @return 返回构造好的url
	 */
	private function __createOauthUrlForCode($redirect_url)
	{
		$url["appid"] = $this->appid;
		$url["redirect_uri"] = "$redirect_url";
		$url["response_type"] = "code";
		$url["scope"] = "snsapi_base";
		$url["state"] = "STATE" . "#wechat_redirect";
		$biz_string = $this->toUrlParamsOpenid($url);
		return "https://open.weixin.qq.com/connect/oauth2/authorize?".$biz_string;
	}
	
	/**
	 * 拼接签名字符串
	 * @param array $url
	 * @return 返回已经拼接好的字符串
	 */
	private function toUrlParamsOpenid($url)
	{
		$buff = "";
		foreach ($url as $k => $v) {
			if ($k != "sign") {
				$buff .= $k . "=" . $v . "&";
			}
		}
		$buff = trim($buff, "&");
		return $buff;
	}
	
	/**
	 * 通过code从工作平台获取openid机器access_token
	 * @param string $code 微信跳转回来带上的code
	 * @return openid
	 */
	public function getOpenidFromMp($code)
	{
		$url = $this->__createOauthUrlForOpenid($code);
		//初始化curl
		$ch = curl_init();
		//设置超时
		curl_setopt($ch, CURLOPT_TIMEOUT, 30);
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
		curl_setopt($ch, CURLOPT_HEADER, false);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		if ($this->curl_proxy_host != "0.0.0.0" && $this->curl_proxy_port != 0) {
			curl_setopt($ch, CURLOPT_PROXY, $this->curl_proxy_host);
			curl_setopt($ch, CURLOPT_PROXYPORT, $this->curl_proxy_port);
		}
		//运行curl，结果以jason形式返回
		$res = curl_exec($ch);
		curl_close($ch);
		//取出openid
		$data = json_decode($res, true);
		$this->data = $data;
		$openid = $data['openid'];
		return $openid;
	}
	
	/**
	 * 构造获取open和access_toke的url地址
	 * @param string $code，微信跳转带回的code
	 * @return 请求的url
	 */
	private function __createOauthUrlForOpenid($code)
	{
		$url["appid"] = $this->appid;
		$url["secret"] = $this->appsecret;
		$url["code"] = $code;
		$url["grant_type"] = "authorization_code";
		$biz_string = $this->toUrlParamsOpenid($url);
		return "https://api.weixin.qq.com/sns/oauth2/access_token?".$biz_string;
	}
	
	
	/**
	 * 设置商品或支付单简要描述
	 **/
	public function setBody($value)
	{
		$this->values['body'] = $value;
	}
	
	/**
	 * 设置附加数据，在查询API和支付通知中原样返回，该字段主要用于商户携带订单的自定义数据
	 **/
	public function setAttach($value)
	{
		$this->values['attach'] = $value;
	}
	
	/**
	 * 设置商户系统内部的订单号,32个字符内、可包含字母, 其他说明见商户订单号
	 **/
	public function setOutTradeNo($value)
	{
		$this->values['out_trade_no'] = $value;
	}
	
	/**
	 * 设置订单总金额，只能为整数，详见支付金额
	 **/
	public function setTotalFee($value)
	{
		$this->values['total_fee'] = $value;
	}
	
	/**
	 * 设置订单生成时间，格式为yyyyMMddHHmmss，如2009年12月25日9点10分10秒表示为20091225091010。其他详见时间规则
	 **/
	public function setTimeStart($value)
	{
		$this->values['time_start'] = $value;
	}
	
	/**
	 * 设置订单失效时间，格式为yyyyMMddHHmmss，如2009年12月27日9点10分10秒表示为20091227091010。其他详见时间规则
	 **/
	public function setTimeExpire($value)
	{
		$this->values['time_expire'] = $value;
	}
	
	/**
	 * 设置商品标记，代金券或立减优惠功能的参数，说明详见代金券或立减优惠
	 **/
	public function setGoodsTag($value)
	{
		$this->values['goods_tag'] = $value;
	}
	
	/**
	 * 设置接收微信支付异步通知回调地址
	 **/
	public function setNotifyUrl($value)
	{
		$this->values['notify_url'] = $value;
	}
	
	/**
	 * 设置取值如下：JSAPI，NATIVE，APP，详细说明见参数规定
	 **/
	public function setTradeType($value)
	{
		$this->values['trade_type'] = $value;
	}
	
	/**
	 * 设置trade_type=JSAPI，此参数必传，用户在商户appid下的唯一标识。下单前需要调用【网页授权获取用户信息】接口获取到用户的Openid。
	 **/
	public function setOpenid($value)
	{
		$this->values['openid'] = $value;
	}
	
	/**
	 * 统一下单，UnifiedOrder中out_trade_no、body、total_fee、trade_type必填
	 * appid、mchid、spbill_create_ip、nonce_str不需要填入
	 * @param int $timeOut
	 * @return 成功时返回，其他抛异常
	 */
	public function unifiedOrder($timeOut = 6)
	{
		$url = "https://api.mch.weixin.qq.com/pay/unifiedorder";
		//检测必填参数
		if (!$this->isOutTradeNoSet()) {
			$this->log("unifiedOrder:缺少统一支付接口必填参数out_trade_no！");
		} else if (!$this->isBodySet()) {
			$this->log("unifiedOrder:缺少统一支付接口必填参数body！");
		} else if (!$this->isTotalFeeSet()) {
			$this->log("unifiedOrder:缺少统一支付接口必填参数total_fee！");
		} else if (!$this->isTradeTypeSet()) {
			$this->log("unifiedOrder:缺少统一支付接口必填参数trade_type！");
		}
		
		//关联参数
		if ($this->getTradeType() == "JSAPI" && !$this->isOpenidSet()) {
			$this->log("unifiedOrder:统一支付接口中，缺少必填参数openid！trade_type为JSAPI时，openid为必填参数！");
		}
		
		//异步通知url未设置，则使用配置文件中的url
 		if (!$this->isNotifyUrlSet()) {
 			$this->setNotifyUrl($this->notify_url);//异步通知url
 		}
		$this->setAppid($this->appid);//公众账号ID
		$this->setMchid($this->mchid);//商户号
		$this->setSpbillCreateIp($_SERVER['REMOTE_ADDR']);//终端ip	   	    
		$this->setNonceStrOrder(self::getNonceStr());//随机字符串
		//签名
		$this->setSignOrder();
		$xml = $this->toXmlOrder();
		$start_time_stamp = self::getMillisecond();//请求开始时间
		//$response = $this->postXmlCurl($xml, $url, false, $timeOut);
		$response = $this->postXmlCurl($xml, $url, true, $timeOut);
		$result = $this->init($response);
		$this->reportCostTime($url, $start_time_stamp, $result);//上报请求花费时间
		return $result;
	}

	/**
	 * 判断商户系统内部的订单号,32个字符内、可包含字母, 其他说明见商户订单号是否存在
	 **/
	public function isOutTradeNoSet()
	{
		return array_key_exists('out_trade_no', $this->values);
	}
	
	/**
	 * 判断商品或支付单简要描述是否存在
	 **/
	public function isBodySet()
	{
		return array_key_exists('body', $this->values);
	}
	
	/**
	 * 判断订单总金额，只能为整数，详见支付金额是否存在
	 **/
	public function isTotalFeeSet()
	{
		return array_key_exists('total_fee', $this->values);
	}
	
	/**
	 * 判断取值如下：JSAPI，NATIVE，APP，详细说明见参数规定是否存在
	 **/
	public function isTradeTypeSet()
	{
		return array_key_exists('trade_type', $this->values);
	}
	
	/**
	 * 获取取值如下：JSAPI，NATIVE，APP，详细说明见参数规定的值
	 **/
	public function getTradeType()
	{
		return $this->values['trade_type'];
	}
	
	/**
	 * 判断trade_type=JSAPI，此参数必传，用户在商户appid下的唯一标识。下单前需要调用【网页授权获取用户信息】接口获取到用户的Openid。 是否存在
	 **/
	public function isOpenidSet()
	{
		return array_key_exists('openid', $this->values);
	}
	
	/**
	 * 判断接收微信支付异步通知回调地址是否存在
	 **/
	public function isNotifyUrlSet()
	{
		return array_key_exists('notify_url', $this->values);
	}
	
	/**
	 * 设置微信支付分配的商户号
	 **/
	public function setMchid($value)
	{
		$this->values['mch_id'] = $value;
	}
	
	/**
	 * 设置微信分配的公众账号ID
	 **/
	public function setAppid($value)
	{
		$this->values['appid'] = $value;
	}

	/**
	 * 设置APP和网页支付提交用户端ip，Native支付填调用微信支付API的机器IP。
	 **/
	public function setSpbillCreateIp($value)
	{
		$this->values['spbill_create_ip'] = $value;
	}
	
	/**
	 * 设置随机字符串，不长于32位。推荐随机数生成算法
	 **/
	public function setNonceStrOrder($value)
	{
		$this->values['nonce_str'] = $value;
	}
	
	/**
	 *
	 * 产生随机字符串，不长于32位
	 * @param int $length
	 * @return 产生的随机字符串
	 */
	public static function getNonceStr($length = 32)
	{
		$chars = "abcdefghijklmnopqrstuvwxyz0123456789";
		$str = "";
		for ($i = 0; $i < $length; $i++) {
			$str .= substr($chars, mt_rand(0, strlen($chars)-1), 1);
		}
		return $str;
	}
	
	/**
	 * 设置签名，详见签名生成算法
	 * @param string $value
	 **/
	public function setSignOrder()
	{
		$sign = $this->makeSign();
		$this->values['sign'] = $sign;
		return $sign;
	}
	
	/**
	 * 生成签名
	 * @return 签名，本函数不覆盖sign成员变量，如要设置签名需要调用SetSign方法赋值
	 */
	public function makeSign()
	{
		//签名步骤一：按字典序排序参数
		ksort($this->values);
		$string = $this->toUrlParamsOrder();
		//签名步骤二：在string后加入KEY
		$string = $string . "&key=" . $this->key;
		//签名步骤三：MD5加密
		$this->log(serialize($this->values));
		$string = md5($string);
		//签名步骤四：所有字符转为大写
		$result = strtoupper($string);
		return $result;
	}
	
	/**
	 * 格式化参数格式化成url参数
	 */
	public function toUrlParamsOrder()
	{
		$buff = "";
		foreach ($this->values as $k => $v) {
			if ($k != "sign" && $v != "" && !is_array($v)) {
				$buff .= $k . "=" . $v . "&";
			}
		}
		$buff = trim($buff, "&");
		return $buff;
	}
	
	/**
	 * 输出xml字符
	 **/
	public function toXmlOrder()
	{
		if (!is_array($this->values) || count($this->values) <= 0) {
			$this->log("toXmlOrder:数组数据异常！");
		}
		$xml = "<xml>";
		foreach ($this->values as $key=>$val) {
			if (is_numeric($val)) {
				$xml.= "<" . $key . ">" . $val . "</" . $key . ">";
			} else {
				$xml.= "<" . $key . "><![CDATA[" . $val . "]]></" . $key . ">";
			}
		}
		$xml.="</xml>";
		return $xml;
	}
	
	/**
	 * 获取毫秒级别的时间戳
	 */
	private static function getMillisecond()
	{
		//获取毫秒的时间戳
		$time = explode (" ", microtime ());
		$time = $time[1] . ($time[0] * 1000);
		$time2 = explode(".", $time);
		$time = $time2[0];
		return $time;
	}
	
	/**
	 * 以post方式提交xml到对应的接口url
	 * @param string $xml  需要post的xml数据
	 * @param string $url  url
	 * @param bool $useCert 是否需要证书，默认不需要
	 * @param int $second   url执行超时时间，默认30s
	 */
	private function postXmlCurl($xml, $url, $useCert = false, $second = 30)
	{
		$ch = curl_init();
		//设置超时
		curl_setopt($ch, CURLOPT_TIMEOUT, $second);
		//如果有配置代理这里就设置代理
		if ($this->curl_proxy_host != "0.0.0.0" && $this->curl_proxy_port != 0) {
			curl_setopt($ch, CURLOPT_PROXY, $this->curl_proxy_host);
			curl_setopt($ch, CURLOPT_PROXYPORT, $this->curl_proxy_port);
		}
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);//严格校验
		//设置header
		curl_setopt($ch, CURLOPT_HEADER, false);
		//要求结果为字符串且输出到屏幕上
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		if ($useCert == true) {
			//设置证书
			//使用证书：cert 与 key 分别属于两个.pem文件
			curl_setopt($ch, CURLOPT_SSLCERTTYPE, 'PEM');
			curl_setopt($ch, CURLOPT_SSLCERT, $this->sslcert_path);
			curl_setopt($ch, CURLOPT_SSLKEYTYPE, 'PEM');
			curl_setopt($ch, CURLOPT_SSLKEY, $this->sslkey_path);
		}
		//post提交方式
		curl_setopt($ch, CURLOPT_POST, true);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $xml);
		//运行curl
		$data = curl_exec($ch);
		//返回结果
		if ($data) {
			curl_close($ch);
			return $data;
		} else {
			$error = curl_errno($ch);
			curl_close($ch);
			$this->log("postXmlCurl:curl出错，错误码:$error");
		}
	}
	
	/**
	 * 将xml转为array并判断签名
	 * @param string $xml
	 */
	public function init($xml)
	{
		$array = $this->fromXml($xml);
		//fix bug 2015-06-29
		if ($array['return_code'] != 'SUCCESS') {
			return $this->getValues();
		}
		$this->checkSign();
		return $this->getValues();
	}
	
	/**
	 * 将xml转为array
	 * @param string $xml
	 */
	public function fromXml($xml)
	{
		if (!$xml) {
			$this->log("fromXml:xml数据异常！");
		}
		//将XML转为array
		//禁止引用外部xml实体
		libxml_disable_entity_loader(true);
		$this->values = json_decode(json_encode(simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA)), true);
		return $this->values;
	}
	
	/**
	 * 获取设置的值
	 */
	public function getValues()
	{
		return $this->values;
	}
	
	/**
	 * 检测签名
	 */
	public function checkSign()
	{
		//fix异常
		if (!$this->isSignSet()) {
			$this->log("checkSign:签名错误1！");
		}
		$sign = $this->makeSign();
		if ($this->getSign() == $sign) {
			return true;
		}
		$this->log("checkSign:签名错误2！");
	}
	
	/**
	 * 判断签名，详见签名生成算法是否存在
	 **/
	public function isSignSet()
	{
		return array_key_exists('sign', $this->values);
	}
	
	/**
	 * 获取签名，详见签名生成算法的值
	 **/
	public function getSign()
	{
		return $this->values['sign'];
	}
	
	/**
	 * 上报数据， 上报的时候将屏蔽所有异常流程
	 * @param string $usrl
	 * @param int $start_time_stamp
	 * @param array $data
	 */
	private function reportCostTime($url, $start_time_stamp, $data)
	{
		//如果不需要上报数据
		if ($this->report_levenl == 0) {
			return;
		}
		//如果仅失败上报
		if (
		    $this->report_levenl == 1 &&
		    array_key_exists("return_code", $data) &&
		    $data["return_code"] == "SUCCESS" &&
		    array_key_exists("result_code", $data) &&
		    $data["result_code"] == "SUCCESS"
        ) {
			return;
		}
			
		//上报逻辑
		$end_time_stamp = self::getMillisecond();
		$this->setInterfaceUrl($url);
		$this->setExecuteTime($end_time_stamp - $start_time_stamp);
		//返回状态码
		if (array_key_exists("return_code", $data)) {
			$this->setReturnCode($data["return_code"]);
		}
		//返回信息
		if (array_key_exists("return_msg", $data)) {
			$this->setReturnMsg($data["return_msg"]);
		}
		//业务结果
		if (array_key_exists("result_code", $data)) {
			$this->setResultCode($data["result_code"]);
		}
		//错误代码
		if (array_key_exists("err_code", $data)) {
			$this->setErrCode($data["err_code"]);
		}
		//错误代码描述
		if (array_key_exists("err_code_des", $data)) {
			$this->setErrCodeDes($data["err_code_des"]);
		}
		//商户订单号
		if (array_key_exists("out_trade_no", $data)) {
			$this->setOutTradeNo($data["out_trade_no"]);
		}
		//设备号
		if (array_key_exists("device_info", $data)) {
			$this->setDeviceInfo($data["device_info"]);
		}
		$this->report();
	}
	
	/**
	 * 设置上报对应的接口的完整URL，类似：https://api.mch.weixin.qq.com/pay/unifiedorder
	 **/
	public function setInterfaceUrl($value)
	{
		$this->values_re['interface_url'] = $value;
	}
	
	/**
	 * 设置接口耗时情况，单位为毫秒
	 **/
	public function setExecuteTime($value)
	{
		$this->values_re['execute_time_'] = $value;
	}
	
	/**
	 * 设置SUCCESS/FAIL此字段是通信标识，非交易标识，交易是否成功需要查看trade_state来判断
	 **/
	public function setReturnCode($value)
	{
		$this->values_re['return_code'] = $value;
	}
	
	/**
	 * 设置返回信息，如非空，为错误原因签名失败参数格式校验错误
	 **/
	public function setReturnMsg($value)
	{
		$this->values_re['return_msg'] = $value;
	}
	
	/**
	 * 设置SUCCESS/FAIL
	 **/
	public function setResultCode($value)
	{
		$this->values_re['result_code'] = $value;
	}
	
	/**
	 * 设置ORDERNOTEXIST—订单不存在SYSTEMERROR—系统错误
	 **/
	public function setErrCode($value)
	{
		$this->values_re['err_code'] = $value;
	}
	
	/**
	 * 设置结果信息描述
	 **/
	public function setErrCodeDes($value)
	{
		$this->values_re['err_code_des'] = $value;
	}
	
	/**
	 * 设置微信支付分配的终端设备号，商户自定义
	 **/
	public function setDeviceInfo($value)
	{
		$this->values_re['device_info'] = $value;
	}
	
	/**
	 * 测速上报，该方法内部封装在report中，使用时请注意异常流程
	 * reportCostTime中interface_url、return_code、result_code、user_ip、execute_time_必填
	 * appid、mchid、spbill_create_ip、nonce_str不需要填入
	 * @param int $timeOut
	 * @return 成功时返回
	 */
	public function report($timeOut = 1)
	{
		$url = "https://api.mch.weixin.qq.com/payitil/report";
		//检测必填参数
		if (!$this->isInterfaceUrlSet()) {
			$this->log("report:接口URL，缺少必填参数interface_url！");
		} 
		if (!$this->isReturnCodeSet()) {
			$this->log("report:返回状态码，缺少必填参数return_code！");
		} 
		if (!$this->isResultCodeSet()) {
			$this->log("report:业务结果，缺少必填参数result_code！");
		} 
		if (!$this->isUserIpSet()) {
			$this->log("report:访问接口IP，缺少必填参数user_ip！");
		} 
		if (!$this->isExecuteTimeSet()) {
			$this->log("report:接口耗时，缺少必填参数execute_time_！");
		}
		$this->setAppidRe($this->appid);//公众账号ID
		$this->setMchidRe($this->mchid);//商户号
		$this->setUserIp($_SERVER['REMOTE_ADDR']);//终端ip
		$this->setTime(date("YmdHis"));//商户上报时间
		$this->setNonceStrRe(self::getNonceStr());//随机字符串
	
		$this->setSignRe();//签名
		$xml = $this->toXmlRe();
	
		$start_time_stamp = self::getMillisecond();//请求开始时间
		//$response = self::postXmlCurl($xml, $url, false, $timeOut);
		$response = self::postXmlCurl($xml, $url, true, $timeOut);
		return $response;
	}
	
	/**
	 * 设置微信支付分配的商户号
	 **/
	public function setMchidRe($value)
	{
		$this->values_re['mch_id'] = $value;
	}
	
	/**
	 * 设置微信分配的公众账号ID
	 **/
	public function setAppidRe($value)
	{
		$this->values_re['appid'] = $value;
	}
	
	/**
	 * 判断上报对应的接口的完整URL，类似：https://api.mch.weixin.qq.com/pay/unifiedorder
	 **/
	public function isInterfaceUrlSet()
	{
		return array_key_exists('interface_url', $this->values_re);
	}
	
	/**
	 * 判断SUCCESS/FAIL此字段是通信标识，非交易标识，交易是否成功需要查看trade_state来判断是否存在
	 **/
	public function isReturnCodeSet()
	{
		return array_key_exists('return_code', $this->values_re);
	}
	
	/**
	 * 判断SUCCESS/FAIL是否存在
	 **/
	public function isResultCodeSet()
	{
		return array_key_exists('result_code', $this->values_re);
	}
	
	/**
	 * 判断发起接口调用时的机器IP 是否存在
	 **/
	public function isUserIpSet()
	{
		return array_key_exists('user_ip', $this->values_re);
	}
	
	/**
	 * 判断接口耗时情况，单位为毫秒是否存在
	 **/
	public function isExecuteTimeSet()
	{
		return array_key_exists('execute_time_', $this->values_re);
	}
	
	/**
	 * 设置发起接口调用时的机器IP
	 **/
	public function setUserIp($value)
	{
		$this->values_re['user_ip'] = $value;
	}
	
	/**
	 * 设置系统时间，格式为yyyyMMddHHmmss，如2009年12月27日9点10分10秒表示为20091227091010。其他详见时间规则
	 **/
	public function setTime($value)
	{
		$this->values_re['time'] = $value;
	}
	
	/**
	 * 设置随机字符串，不长于32位。推荐随机数生成算法
	 **/
	public function setNonceStrRe($value)
	{
		$this->values_re['nonce_str'] = $value;
	}

	/**
	 * 设置签名，详见签名生成算法
	 * @param string $value
	 **/
	public function setSignRe()
	{
		$sign = $this->makeSignRe();
		$this->values_re['sign'] = $sign;
		return $sign;
	}
	
	/**
	 * 生成签名
	 * @return 签名，本函数不覆盖sign成员变量，如要设置签名需要调用SetSign方法赋值
	 */
	public function makeSignRe()
	{
		//签名步骤一：按字典序排序参数
		ksort($this->values_re);
		$string = $this->toUrlParamsRe();
		//签名步骤二：在string后加入KEY
		$string = $string . "&key=" . $this->key;
		//签名步骤三：MD5加密
		$this->log(serialize($this->values_re));
		$string = md5($string);
		//签名步骤四：所有字符转为大写
		$result = strtoupper($string);
		return $result;
	}
	
	/**
	 * 格式化参数格式化成url参数
	 */
	public function toUrlParamsRe()
	{
		$buff = "";
		foreach ($this->values_re as $k => $v) {
			if ($k != "sign" && $v != "" && !is_array($v)) {
				$buff .= $k . "=" . $v . "&";
			}
		}
		$buff = trim($buff, "&");
		return $buff;
	}
	
	/**
	 * 输出xml字符
	 **/
	public function toXmlRe()
	{
		if (!is_array($this->values_re) || count($this->values_re) <= 0) {
			$this->log("toXmlRe:数组数据异常！");
		}
		$xml = "<xml>";
		foreach ($this->values_re as $key=>$val) {
			if (is_numeric($val)) {
				$xml.= "<" . $key . ">" . $val . "</" . $key . ">";
			} else {
				$xml.= "<" . $key . "><![CDATA[" . $val . "]]></" . $key . ">";
			}
		}
		$xml.="</xml>";
		return $xml;
	}
	
	/**
	 *
	 * 获取jsapi支付的参数
	 * @param array $unified_order_result 统一支付接口返回的数据
	 * @return json数据，可直接填入js函数作为参数
	 */
	public function getJsApiParameters($unified_order_result)
	{
		if (
		!array_key_exists("appid", $unified_order_result) ||
		!array_key_exists("prepay_id", $unified_order_result) ||
		$unified_order_result['prepay_id'] == ""
		) {
			$this->log("getJsApiParameters:参数错误");
		}
		$this->setAppidJs($unified_order_result["appid"]);
		$time_stamp = time();
		$this->setTimeStamp("$time_stamp");
		$this->setNonceStrJs($this->getNonceStr());
		$this->setPackage("prepay_id=" . $unified_order_result['prepay_id']);
		$this->setSignType("MD5");
		$this->setPaySign($this->makeSignJs());
		$parameters =json_encode($this->getValuesJs());
		$this->log($parameters);
		return $parameters;
	}
	
	/**
	 * 设置微信分配的公众账号ID
	 **/
	public function setAppidJs($value)
	{
		$this->values_js['appId'] = $value;
	}
	
	/**
	* 设置支付时间戳
	**/
	public function setTimeStamp($value)
	{
		$this->values_js['timeStamp'] = $value;
	}
	
	/**
	* 随机字符串
	**/
	public function setNonceStrJs($value)
	{
		$this->values_js['nonceStr'] = $value;
	}
	
	/**
	* 设置订单详情扩展字符串
	**/
	public function setPackage($value)
	{
		$this->values_js['package'] = $value;
	}
	
	/**
	* 设置签名方式
	**/
	public function setSignType($value)
	{
		$this->values_js['signType'] = $value;
	}
	
	/**
	* 设置签名方式
	**/
	public function setPaySign($value)
	{
		$this->values_js['paySign'] = $value;
	}
	
	/**
	 * 生成签名
	 * @return 签名，本函数不覆盖sign成员变量，如要设置签名需要调用SetSign方法赋值
	 */
	public function makeSignJs()
	{
		//签名步骤一：按字典序排序参数
		ksort($this->values_js);
		$string = $this->toUrlParamsJs();
		//签名步骤二：在string后加入KEY
		$string = $string . "&key=" . $this->key;
		//签名步骤三：MD5加密
		$this->log(serialize($this->values_js));
		$string = md5($string);
		//签名步骤四：所有字符转为大写
		$result = strtoupper($string);
		return $result;
	}
	
	public function toUrlParamsJs()
	{
		$buff = "";
		foreach ($this->values_js as $k => $v) {
			if ($k != "sign" && $v != "" && !is_array($v)) {
				$buff .= $k . "=" . $v . "&";
			}
		}
		$buff = trim($buff, "&");
		return $buff;
	}

	/**
	 * 获取设置的值
	 */
	public function getValuesJs()
	{
		return $this->values_js;
	}

	/**
	 * 获取地址js参数
	 * @return 获取共享收货地址js函数需要的参数，json格式可以直接做参数使用
	 */
	public function getEditAddressParameters()
	{
		$get_data = $this->data;
		$data = array();
		$data["appid"] = $this->appid;
		$data["url"] = "http://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
		$time = time();
		$data["timestamp"] = "$time";
		$data["noncestr"] = "1234568";
		$data["accesstoken"] = $get_data["access_token"];
		ksort($data);
		$params = $this->toUrlParamsOpenid($data);
		$addrSign = sha1($params);
	
		$after_data = array(
		    "addrSign" => $addrSign,
			"signType" => "sha1",
			"scope" => "jsapi_address",
			"appId" => $this->appid,
			"timeStamp" => $data["timestamp"],
			"nonceStr" => $data["noncestr"]
		);
		$parameters = json_encode($after_data);
		return $parameters;
	}
	
	//log日志
	public function log($word)
	{
		$log_name = $this->log;
		$fp = fopen($log_name, "a");
		flock($fp, LOCK_EX);
		fwrite($fp, "执行日期：" . strftime("%Y-%m-%d-%H:%M:%S", time()) . "\n" . $word . "\n\n");
		flock($fp, LOCK_UN);
		fclose($fp);
	}
	
	//设置日志路径
	public function setLog($log)
	{
		$this->log = $log;
		return $this;
	}
	
}