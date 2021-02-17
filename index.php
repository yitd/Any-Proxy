<?php
class AnyProxy {
	
	public $anyIp = 1;
	public $host, $path, $https, $curl;
	
	/*
	* isHttps 判断是否是 Https 请求
	* return: boolean
	*/
	public function isHttps()
	{
		return ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == "on") || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == "https")) ? "https://" : "http://";
	}
	
	/*
	* deleteCookie 删除所有 Cookie
	* return: void
	*/
	public function deleteCookie()
	{
		foreach ($_COOKIE as $key => $value) {
			setcookie($key, null, time() - 3600, "/");
		}
	}
	
	/*
	* getClientHeader 获得客户端请求的 Header
	* return: array
	*/
	public function getClientHeader()
	{
		$headers = array();
		foreach($_SERVER as $k => $v) {
			if(strpos($k, 'HTTP_') === 0) {
				$k = strToLower(preg_replace('/^HTTP/', '', $k));
				$k = preg_replace_callback('/_\w/', 'header_callback', $k);
				$k = preg_replace('/^_/', '', $k);
				$k = str_replace('_', '-', $k);
				if ($k == 'Host') continue;
				$headers[] = "{$k}: {$v}";
			}
		}
		return $headers;
	}
	
	/*
	* parseHeader 解析 CURL 返回的 Header 和 Body
	* param:
	*    $response 返回的 Response
	* return: array
	*/
	public function parseHeader($response)
	{
		list($headerStr, $response) = explode("\r\n\r\n", $response, 2);
		$headerStr = $headerStr ?? "";
		$headers   = array($headerStr, $response);
		if(preg_match('/^HTTP\/1\.1 \d{3}/', $response)) {
			$headers = $this->parseHeader($response);
		}
		return $headers;
	}
	
	/*
	* arrayToString 数组转为字符串
	* param:
	*    $array 要处理的数组
	* return: array
	*/
	public function arrayToString($array) {
		$string = "";
		if (is_array($array)) {
			foreach ($array as $key => $value) {
				$string .= (!empty($string)) ? "; {$key}={$value}" : "{$key}={$value}";
			}
		} else {
			$string = $array;
		}
		return urldecode($string);
	}
	
	/*
	* generateIpv4 生成随机的 IPv4 地址
	* return: string
	*/
	public function generateIpv4()
	{
		return mt_rand(1,255) . "." . mt_rand(1,255) . "." . mt_rand(1,255) . "." . mt_rand(1,255);
	}
	
	/*
	* createRequest 创建 CURL 请求
	* param:
	*    $url      要请求的地址
	*    $postData 要通过 POST 发送的内容
	*    $headers  要发送的 Headers
	* return: resource
	*/
	public function createRequest($url, $postData, $headers)
	{
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_HEADER, true);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_FOLLOWLOCATION, 1);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
		curl_setopt($curl, CURLOPT_TIMEOUT, 10);
		curl_setopt($curl, CURLOPT_BINARYTRANSFER, true);
		
		if(is_array($postData)) {
			curl_setopt($curl, CURLOPT_POST, 1);
			curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($postData));
		}
		
		if(is_array($headers)) {
			curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
		}
		
		return $curl;
	}
	
	/*
	* executeRequest 执行 CURL 请求
	* param:
	*    $curl 要执行的 CURL 请求资源
	* return: string
	*/
	
	public function executeRequest($curl)
	{
		return curl_exec($curl);
	}
	
	/*
	* isExit 检查是否为退出页面的请求
	* return: void
	*/
	public function isExit()
	{
		if(is_string($this->path) && substr($this->path, -2) == "~q") {
			$this->deleteCookie();
			Header("Location: " . $this->https . $this->host);
			Exit;
		}
	}
	
	/*
	* handleRequest 处理客户端请求
	* return: void
	*/
	public function handleRequest()
	{
		if (substr($this->path, 1, 7) == "http://" || substr($this->path, 1, 8) == "https://" || isset($_POST['urlss'])) {
			if(!empty($_POST['urlss'])) {
				$url = trim($_POST['urlss']);
			} else {
				$url = substr($this->path, 1);
			}
			if(substr($url, 0, 4) !== "http") {
				$url = "http://{$url}";
			}
			
			$pageUrl = parse_url($url);
			$query   = $pageUrl['query'] ? "?{$PageUrl['query']}" : "";
			$scheme  = $pageUrl['scheme'] . "://";
			$fullUrl = $https . $host . $pageUrl['path'] . $query;
			
			$this->deleteCookie();
			SetCookie("urlss", $scheme . $pageUrl['host'], 0, "/");
			Header("Location: " . $fullUrl);
			Exit;
		} elseif(!isset($_COOKIE['urlss']) || empty($_COOKIE['urlss'])) {
			Exit(str_replace("[[HOST]]", $this->https . $this->host, file_get_contents("default_page_template.html")));
		}
	}
	
	/*
	* isInvalidIp 判断是否是无效的 IP 地址
	* param:
	*    $host 要判断的域名或 IP
	* return: boolean
	*/
	public function isInvalidIp($host)
	{
		$hostIp = gethostbyname($host);
		if(filter_var($hostIp, FILTER_VALIDATE_IP)) {
			return (filter_var($hostIp, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false);
		}
		return false;
	}
	
	/*
	* warningExit 弹出警告并退出
	* param:
	*    $text 要显示的警告消息内容
	* return: void
	*/
	public function warningExit($text)
	{
		Header("HTTP/1.1 403 Forbidden");
		Exit("<script>alert('{$text}');window.location.href='{$this->https}{$this->host}';</script>");
	}
	
	/*
	* convertCharset 转换字符串的格式
	* param:
	*    $text 要处理的字符串
	* return: string
	*/
	public function convertCharset($text)
	{
		$charlen = stripos($text, "charset");
		if (stristr(substr($text, $charlen, 18) , "GBK") || stristr(substr($text, $charlen, 18) , "GB2312")) {
			$text = mb_convert_encoding($text, "UTF-8", "GBK,GB2312,BIG5");
		}
		return $text;
	}
	
	/*
	* getRemoteIp 获取客户端的 IP 地址
	* return: string
	*/
	public function getRemoteIp()
	{
		if($this->anyIp == 1) {
			$remoteIp = $_SERVER['HTTP_CLIENT_IP'] ?? $_SERVER['REMOTE_ADDR'];
		} elseif($anyip == 2) {
			$remoteIp = $this->generateIpv4();
		} elseif(empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
			$remoteIp = $_SERVER['REMOTE_ADDR'];
		} else {
			$remoteIp = $_SERVER['HTTP_X_FORWARDED_FOR'];
		}
		return $remoteIp;
	}
	
	/*
	* getPostData 获取客户端发送的 POST 数据
	* return: array | boolean
	*/
	public function getPostData()
	{
		return ($_SERVER['REQUEST_METHOD'] == 'POST') ? $_POST : false;
	}
	
	/*
	* getSendHeaders 获取客户端发送的 Headers
	* param:
	*    $protocalHost 客户端请求的主机名
	* return: array
	*/
	public function getSendHeaders($protocalHost)
	{
		$referer  = isset($_SERVER['HTTP_REFERER']) ? str_replace($this->host, $protocalHost['host'], $_SERVER['HTTP_REFERER']) : $this->https . $this->host;
		$remoteIp = $this->getRemoteIp();
		$headers  = [
			"Accept-language: {$_SERVER['HTTP_ACCEPT_LANGUAGE']}",
			"Referer: {$referer}",
			"CLIENT-IP: {$remoteIp}",
			"X-FORWARDED-FOR: {$remoteIp}",
			"Cookie: " . $this->arrayToString($_COOKIE),
			"User-Agent: {$_SERVER['HTTP_USER_AGENT']}",
		];
		return $headers;
	}
	
	/*
	* isRedirect 检测服务器是否返回了重定向
	* param:
	*    $protocalHost 客户端请求的主机名
	* return: void
	*/
	public function isRedirect($protocalHost)
	{
		$locUrl = parse_url(curl_getinfo($this->curl, CURLINFO_EFFECTIVE_URL));
		if("{$locUrl['scheme']}://{$locUrl['host']}" !== "{$protocalHost['scheme']}://{$protocalHost['host']}") {
			SetCookie("urlss", "{$locUrl['scheme']}://{$locUrl['host']}", 0, "/");
		}
	}
	
	/*
	* sendReponseHeader 发送远程服务器返回的 Headers
	* param:
	*    $response 远程服务器返回的内容
	*    $root     主域名
	*    $top      域名后缀
	* return: string
	*/
	public function sendReponseHeader($response, $root, $top)
	{
		list($headerStr, $response) = $this->parseHeader($response);
		$headers = explode("\n", $headerStr);
		foreach($headers as $header) {
			if(strlen($header) > 0) {
				if(strpos($header, 'ETag') !== false) continue;
				if(strpos($header, 'Connection') !== false) continue;
				if(strpos($header, 'Cache-Control') !== false) continue;
				if(strpos($header, 'Content-Length') !== false) continue;
				if(strpos($header, 'Transfer-Encoding') !== false) continue;
				if(strpos($header, 'HTTP/1.1 100 Continue') !== false) continue;
				if(strpos($header, 'Strict-Transport-Security') !== false) continue;
				if(strpos($header, 'Set-Cookie') !== false) {
					$targetCookie = "{$header};";
					// 如果返回到客户端cookie不正常可把下行中的 {$root}{$top} 换成 {$this->host}
					$responseCookie = preg_replace("/domain=.*?;/", "domain={$root}{$top};", $targetCookie);
					$header = substr($responseCookie, 0, strlen($responseCookie) - 1);
					Header($header, false);
				} else {
					Header($header);
				}
			}
		}
		return $response;
	}
	
	/*
	* parseRequest 解析请求，主要请求部分
	* return: string
	*/
	public function parseRequest()
	{
		$targetHost = $_COOKIE['urlss']; // 代理的域名及使用的协议最后不用加 /
		
		if(substr($targetHost, 0, 4) !== "http") {
			$targetHost = "http://{$targetHost}";
		}
		
		$protocalHost = parse_url($targetHost);         // 处理代理的主机得到协议和主机名称
		$rootDomain   = explode(".", $this->host);      // 以.分割域名字符串
		$length       = count($rootDomain);             // 获取数组的长度
		$top          = "." . $rootDomain[$length - 1]; // 获取顶级域名
		$root         = "." . $rootDomain[$length - 2]; // 获取主域名
		
		// 判断请求的域名或ip是否合法
		if(strstr($targetHost, ".") === false || $protocalHost['host'] == $this->host) {
			$this->deleteCookie();
			$this->warningExit("请求的域名不合法！");
		}
		if($this->isInvalidIp($protocalHost['host'])) {
			$this->deleteCookie();
			$this->warningExit("请求的 IP 不合法！");
		}
		
		$mainUrl  = $protocalHost['scheme'] . "://" . $protocalHost['host'] . $this->path;
		$postData = $this->getPostData();
		$headers  = $this->getSendHeaders($protocalHost);
		
		if($postData !== false) {
			$headers[] = "Content-Type: {$_SERVER['CONTENT_TYPE']}";
		}
		
		$this->curl = $this->createRequest($mainUrl, $postData, $headers);
		$response   = $this->executeRequest($this->curl);
		
		// 判断请求url是否被重定向
		$this->isRedirect($protocalHost);
		$response = $this->sendReponseHeader($response, $root, $top);

		// 解决中文乱码
		$response = $this->convertCharset($response);
		$response = str_replace("http://" . $protocalHost['host'], $this->https . $this->host, $response);
		$response = str_replace("https://" . $protocalHost['host'], $this->https . $this->host, $response);
		
		// 关闭并释放 CURL 资源
		curl_close($this->curl);
		return $response;
	}
}

$anp = new AnyProxy();

$anp->host  = $_SERVER['HTTP_HOST'];
$anp->path  = $_SERVER['REQUEST_URI'];
$anp->https = $anp->isHttps();
$anp->anyIp = 1; // $anyIp 值为 1 发送服务器 IP 头，值为 2 则发送随机 IP，值为 3 发送客户端 IP，仅在部分网站中有效

$anp->isExit();
$anp->handleRequest();

Header("Pragma: no-cache");
echo $anp->parseRequest();
Exit;
