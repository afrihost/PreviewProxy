<?php
#
# Preview proxy
#
# This code is copyright 2012 Afrihost.com
# Redistribution is permitted under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
# (ie. If you use this code, you must distribute it to your users, together with your modifications)
# See http://www.gnu.org/licenses/agpl.html

#ini_set('default_charset','UTF-8');
# Don't squeak on bad html
function get_execution_time()
{
	static $start_time = null;
	if($start_time)
		return microtime(true) - $start_time;
	$start_time = microtime(true);
}
get_execution_time();

libxml_use_internal_errors(true);

function myurlencode($url) {
	$r=urlencode($url);
	$r=str_replace('%3A',':',$r);
	$r=str_replace('%2F','/',$r);
	return $r;
}


if( !function_exists('apache_request_headers') ) {
	function apache_request_headers() {
	  $arh = array();
	  $rx_http = '/\AHTTP_/';
	  foreach($_SERVER as $key => $val) {
	    if( preg_match($rx_http, $key) ) {
	      $arh_key = preg_replace($rx_http, '', $key);
	      $rx_matches = array();
	      // do some nasty string manipulations to restore the original letter case
	      // this should work in most cases
	      $rx_matches = explode('_', $arh_key);
	      if( count($rx_matches) > 0 and strlen($arh_key) > 2 ) {
		foreach($rx_matches as $ak_key => $ak_val) $rx_matches[$ak_key] = ucfirst($ak_val);
		$arh_key = implode('-', $rx_matches);
	      }
	      $arh[$arh_key] = $val;
	    }
	  }
	  return( $arh );
	}
}

# Look up the host at our preferred DNS server
function dns_lookup($hostname) {
	if (!$hostname) {
		return '';
	}
	if (!PreviewConfig::PREFERRED_DNS) {
		$ip=gethostbyname($hostname);
		if (PreviewConfig::CHECK_WILDCARD && $ip==gethostbyname("wildcardcheck")) {
			return '';
		}
		return $ip;
	}
	$dns=shell_exec('dig @'.escapeshellarg(PreviewConfig::PREFERRED_DNS).' '.escapeshellarg($hostname));
	#echo $dns;
	# ;; ANSWER SECTION:
	# preview.afrihost.com.	7200	IN	A	41.76.213.51
	if (! preg_match('/;; ANSWER SECTION:.*?\bA\s+(\d+\.\d+\.\d+\.\d+)\b/s',$dns,$matches) ) {
		$ip=gethostbyname($hostname);
		if (PreviewConfig::CHECK_WILDCARD && $ip==gethostbyname("wildcardcheck")) {
			return '';
		}
		return $ip;
	}
	#print_r ($matches);
	return $matches[1];
}

/* Figure out if the host1 is the same as the host we are previewing - e.g www. */
function samehost($host1, $host2)
{
	if ($host1==$host2) return True;
	$host1= strtolower($host1);
	$host2= strtolower($host2);
	if ($host1==$host2) return True;
	if ($host1=="www.$host2") return True;
	if ("www.$host1"==$host2) return True;
	return False;
}

function previewurl() {
	return 'http://'.$_SERVER['HTTP_HOST'].'/';
}

function rewrite_url($src) {
	global $url, $ip;
	if (preg_match('/^(#|mailto:|data:|javascript:|about:|chrome:)/i',$src)) {
		#error_log("$osrc .. $src\n");
		return $src;
	}
	$osrc=$src;
	if (substr($src,0,2)=='//') {
		# Transform relative-to-protocol to http only
		$src='http:'.$src;
	}
	else if (substr($src,0,1)=='/') {
		# Transform relative-to-site to absolute: $url here is the URL of the site as seen by the target server, $src starts as /moo and ends as http://proxy/1.2.3.4/moo
		$parse_url = parse_url($url);
		$src=$parse_url['scheme'].'://'.  $parse_url['host'].$src; # no support for embedded auth
	}
	else if (strpos($src,'://')===FALSE) {
		$parse_url = parse_url($url);
		$relative=@$parse_url['path'];
		if ($relative=='') {$relative='/';}
		$newpath=substr($relative,0,strrpos($relative,'/')+1).$src;
		$realpath=array();
		$pathbits=explode('/',$newpath);
		foreach ($pathbits as $bit) {
			if ($bit=='..') {array_pop($realpath); continue;}
			$realpath[]=$bit;
		}
		$realpath=implode('/',$realpath);
		if (substr($realpath,0,1)!='/') $realpath='/'.$realpath;
		$src=$parse_url['scheme'].'://'.  $parse_url['host'].$realpath;
		$src=preg_replace('{(://[a-zA-Z0-9-._]+/+)\.\./+}','$1',$src);   # redo links relative to /
	}
	# Not quite sure what this code was here for ...
	#else if (preg_match('|^https?://|',$src)) {
	#	return $src;
	#}
	$src_url = parse_url($src);
	$base_url = parse_url($url);
	if (!PreviewConfig::PROMISCUOUS && ! samehost($src_url['host'], $base_url['host'] ))  {
		#error_log("$osrc .. $src\n");
		return $src;  // your browser can have this URL as-is
	}
	#$return = 'http://'.$_SERVER['HTTP_HOST'].
	#	substr($_SERVER["REQUEST_URI"],0,strpos($_SERVER["REQUEST_URI"],'?')).
	#	'?ip='.$ip.
	#	'&url='.myurlencode($src);
	$return = previewurl() . $ip.'/'.$src; # myurlencode was here ...
	#DEBUG::
	#if ($osrc!=$src) {
	#	$return .=  '&osrc='.myurlencode($osrc);
	#}
	#error_log("$osrc .. $return\n");
	return $return;
}

function globalvariablelookup($matches)
{
	global $stats;
	$m=$matches[1];
	$r= @$stats[$m];
	if ($r) return $r;
	return $m;
}
function refresh_callback($matches)
{
	$m=$matches[1];
	$quote='';
	if ( (substr($m,0,1)=='"' && substr($m,-1,1)=='"') || (substr($m,0,1)=='\'' && substr($m,-1,1)=='\'') ) {
		$quote=substr($m,0,1);
		$m=substr($m,1,strlen($m)-2);
	}
	return ';URL='.$quote.rewrite_url($m).$quote;
}
function css_callback($matches)
{
	$m=$matches[1];
	$quote='';
	if ( (substr($m,0,1)=='"' && substr($m,-1,1)=='"') || (substr($m,0,1)=='\'' && substr($m,-1,1)=='\'') ) {
		$quote=substr($m,0,1);
		$m=substr($m,1,strlen($m)-2);
	}
	return 'url('.$quote.rewrite_url($m).$quote.')';
}
function rewrite_stylesheet_urls($text)
{
	# :url(//ssl.gstatic.com/gb/images/b_8d5afc09.png)
	return preg_replace_callback('/\burl\(([^)]*)\)/i',"css_callback",$text);
}

function script_callback($matches)
{
	$m=$matches[2];
	return $matches[1].rewrite_url($m).$matches[3];
}
function script_callback_weird($matches)
{
	$m=$matches[1].'?XXXXXXXXX';
	$m=stripslashes($m);
	$n=rewrite_url($m);
	if ($n==$m) {return $matches[1]; }
	$n = preg_replace(':/:','\\/',$n);
	return $n;
}
function rewrite_script_urls($text)
{
	# :url(//ssl.gstatic.com/gb/images/b_8d5afc09.png)
	$text = preg_replace_callback('{(\b|[\'"])(https?://[^/ ]+[^/ ]/)(\b|[\'"])}',"script_callback",$text);
	# Weird escaped http:\/\/ type URLs for MCE editor as used in wordpress: this is done so CDATA sections don't end prematurely, it seems
	$text = preg_replace_callback('{\b(https?:\\\\/\\\\/\S+\.([^ \"\',/]*\\\\/)+)\b}',"script_callback_weird",$text);
	return $text;
}

function tag_attribute_url_rewrite($DOM, $tag, $attribute) {
	/* Rewrite URL attributes (e.g. a href, img src) */
	$items = $DOM->getElementsByTagName($tag);
	for ($i = 0; $i < $items->length; $i++) {
		$href = $items->item($i)->getAttribute($attribute);
		if (!$href) continue;
		$nhref=rewrite_url($href);
		if ($nhref!==$href) {
			$items->item($i)->setAttribute($attribute,$nhref);
		}
	}
}

function tag_attribute_style_rewrite($DOM, $tag, $attribute) {
	/* Rewrite style attributes */
	$items = $DOM->getElementsByTagName($tag);
	for ($i = 0; $i < $items->length; $i++) {
		$src = $items->item($i)->getAttribute($attribute);
		if (!$src) continue;
		$items->item($i)->setAttribute($attribute,rewrite_stylesheet_urls($src));
	}
}

function tag_attribute_meta_rewrite($DOM) {
	/* Rewrite style attributes */
	$items = $DOM->getElementsByTagName('meta');
	for ($i = 0; $i < $items->length; $i++) {
		$src = $items->item($i)->getAttribute('http-equiv');
		if (!$src || strtolower(trim($src))!='refresh') continue;
		$attribute='content';
		$src = $items->item($i)->getAttribute($attribute);
		if (!$src) continue;
		$src = preg_replace_callback('/;URL=(.*)/i',"refresh_callback",$src);
		$items->item($i)->setAttribute($attribute,$src);
	}
}

function form() {
	global $url;
	global $ip;
	if ($url && !$ip) {
		$parse_url = parse_url($url);
		$ip=dns_lookup($parse_url['host']);
	}
	echo file_get_contents("header.html");
	?>
This proxy server allows you to see what your web site will look like before DNS changes are complete.
<p>
Enter the URL of your new site below, and enter the IP address of the server
where it is set up. Click the button to see what it will look like when
the DNS has updated:
	<form action="<?php echo previewurl(); ?>">
	<label for="url">URL to preview:</label><input type="text" name="url" id="url" size=50 autofocus="True" value="<?php echo $url; ?>" class="input">
	&nbsp;
	<label for="ip"  style="margin-left: 1em;">Server IP address:</label><input type="text" name="ip" id="ip" value="<?php echo $ip; ?>" class="input">
	&nbsp;
	<label>&nbsp;</label></td><td><input type="submit" id="q" name="q" value="Preview">
	</table>
	</form>
	<?php
	echo file_get_contents("footer.html");
	exit();
}

function http_url($url) {
	if ($url && !preg_match('|^https?://|',$url)) { $url='http://'.$url; }
	return $url;
}
function report_error($message,$debug='')
{
	global $url, $ip;
	header("HTTP/1.0 502 Proxy Error"); # you figure it out
	echo file_get_contents('header.html').
		"<H1>Error: $message</H1>".
		'Cannot retrieve <a href="'.urlencode($url).'">'.htmlentities($url).'</a>'.
		' from '.htmlentities($ip).'<p>'.$debug.
		 file_get_contents('footer.html');
	exit();
}
function go() {
	$debuginfo = '';
	global $url, $ip;
	if (defined('PreviewConfig::DEBUG') && PreviewConfig::DEBUG && @$_GET['debugme']=='phpinfo') {
		phpinfo();
		exit;
	}
	# Now get it directly from the URI
	$bits=explode('/',$_SERVER["REQUEST_URI"]);
	$ip=array_shift($bits);  # empty part
	$ip=array_shift($bits);  # IP part
	$request_url=implode('/',$bits);
	$request_url=preg_replace('|^(https?:)//*|','$1//',$request_url);  # correct mangling from http://site to http:/site
	#echo "ip=$ip, url=$url";
	# If IP is missing, then follow regular assumptions ... except it's hard to know that the IP is missing!
	if (preg_match('|^https?:|',$ip)) {
		# URL with scheme preview.moo/$ip=http://$bits[1]=target.com/$bits[2]=stuff
		$bits=explode('/',$_SERVER["REQUEST_URI"]);
		array_shift($bits);
		$request_url=implode('/',$bits);
		$request_url=preg_replace('!^(https?:)|//*!','$1//',$request_url);  # correct mangling from http://site to http:/site
		$ip='';
	}
	# If we don't have a proper picture of what we're doing, then show the form:
	else if (! $ip || ! $request_url || (@$_GET['url'] && @$_GET['ip'] ) || substr($ip,0,1)=='?') {
		$url=@$_GET['url'];
		$ip=@$_GET['ip'];
		if (!$url) {
			$url=substr($_SERVER["REQUEST_URI"],1);
		}
		$url=http_url($url);
		if ($url && $ip) {
			if (preg_match('/[a-z]/i',$ip)) {
				$ip=gethostbyname($ip);
			}
			$newurl = previewurl(). $ip.'/'.$url; # myurlencode here .. was ..
			header("Location: $newurl");
			echo "Redirect to $newurl";
			exit();
		}
		form();
	}

	$url=http_url($request_url);
	# echo "ip=$ip, bits=".print_r($bits,1).", url=$url, request_url=$request_url, host=$host, $parse_url=".print_r($parse_url)."<br>";
	#echo "HOST=$url url=$request_url ".print_r($parse_url,1)."::";
	$parse_url = parse_url($url);
	$host = $parse_url['host'];
	if (!strpos($host,'.')) {
		$url=http_url(substr($_SERVER['REQUEST_URI'],1));
		form();
	}
	#print_r($parse_url);
	$curl = curl_init(); # $url);
	if (!$ip) {$ip=dns_lookup($host);}
	# Append DNS_SEARCH suffix to unqualified names before using them
	if (PreviewConfig::DNS_SEARCH && strpos($ip,'.')===FALSE) {
		$ip .= '.'.PreviewConfig::DNS_SEARCH;
	}
	$ip=gethostbyname($ip);
	if (substr($ip,0,3)=="127" || !preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/',$ip)) {
		report_error('Invalid host '.htmlentities($ip));
	}
	if (PreviewConfig::PARANOID) {
		$route=shell_exec('/sbin/ip route get "'.$ip.'"');
		if (strpos($route,'dev lo')) {
			die('You are browsing localhost');  # you's browsing localhost or ipv6 or is injecting shellscripzt
		}
	}
	$ok=PreviewConfig::PROMISCUOUS;
	$config=new PreviewConfig();
	foreach ($config->whitelist as $re) {
		if (preg_match($re,$ip)) { $ok=True; }
	}
	foreach ($config->blacklist as $re) {
		if (preg_match($re,$ip)) {
			header("Location: $url",true,307); # straightforward redirect for blacklist
			exit();
		}
	}
	if (! $ok) {
		$hostiplist=gethostbynamel($host);
		if (!$hostiplist || ! in_array($ip,$hostiplist) ) {
			// we're okay here ! (phew!)
		}
		# If it's not a preview, then let's redirect you to the right place:
		else if (!preg_match('{(\.htm|\.php|/$|^http://[^/]*$)}i',$url)) {
			header("Location: $url",true,307); # straightforward redirect
			exit();
		} else {
			$header = file_get_contents("header.html");
			$refresh='<meta http-equiv="refresh" content="5;URL=\''.$url.'\'" />';
			$header = preg_replace(':<head>:',"<head>$refresh",$header);
			$header = preg_replace(':<title>.*?</title>:',"<title>Site already live!</title>",$header);
			echo $header . '
		<h2>Site already live!</h2>
		<p><b>Good news!</b> The public DNS records for <a href="'.$host.'">'.htmlentities($host).'</a> already point to
		'.htmlentities($ip).', so you can view it without this preview facility.
		<p>Your browser will redirect there in 5 seconds ...</p>
		<form action="'. previewurl() . '">
		To view this site at another IP address, click:
			<input type=hidden name="url" value="'.htmlentities($url).'">
			<input type=submit name=preview value="Change IP address" autofocus=True>
		</form>
		Well, to be accurate, when we checked the DNS records from
		<i>here</i> we found that they are alive and well, and pointing
		to your site.  It is possible that your resolving DNS server
		will be holding on to the memory that the domain does not exist
		for the next few minutes.  If you get an error, try again every
		ten minutes (DNS servers keep memory of non-existent domains
		for ten minutes).'.file_get_contents('footer.html');
		exit();
		}
	}
	#$debuginfo='';
	#$debuginfo.="<br>Host: $host";
	$request_headers = array('Host: '.$host);
	$request_headers[] = 'X-Preview: 1';
	$curl_url = preg_replace("/$host/i",$ip,$url,1);
	# error_log("host=$host, ip=$ip, $url => $curl_url");
	curl_setopt($curl, CURLOPT_URL, $curl_url); # fixme: errors if you embed the IP in the URL
	#$debuginfo.="<br>curl_url: $curl_url";
	foreach (apache_request_headers() as $browser_header=>$browser_value) {
		if (preg_match('/^(X-|Accept$|DNT|Cache-Control|Accept-Language|Authorization|If-Modified-Since)/i',$browser_header)) {
			$request_headers[]=$browser_header.': '.$browser_value;
		}
	}
	curl_setopt($curl, CURLOPT_HTTPHEADER, $request_headers);
	#$debuginfo.="<br>request_headers: ".implode('; ',$request_headers);
	curl_setopt($curl, CURLOPT_USERAGENT, @$_SERVER['HTTP_USER_AGENT']);
	curl_setopt($curl, CURLOPT_HEADER, true);
	curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($curl, CURLOPT_CONNECTTIMEOUT,180);
	curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
	curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, FALSE);
	#echo "_COOKIE::"; print_r($_COOKIE);
	if (count($_COOKIE)) {
		$allcookies=array();
		foreach ($_COOKIE as $k => $v) {
			# rcookie idea was kinda nice, but blah
			#if (substr($k,0,8)=="rcookie_") {
			#	# echo "::sending COOKIE: $v<br>";
			#	$allcookies[]=$v;
			#}
            if (is_array($v)) {
                foreach ($v as $ss => $val) {
                    $allcookies[]=$k.'['.$ss.']='.urlencode($val); # unsolicited cookies from javascript .. ?
                }
            }
            else {
                $allcookies[]=$k.'='.urlencode($v); # unsolicited cookies from javascript .. ?
            }
		}
		curl_setopt($curl,CURLOPT_COOKIE, implode('; ',$allcookies));
		#$debuginfo.="<br>cookies: ".implode('; ',$allcookies);
	}
	if (count($_POST)) {
		curl_setopt($curl, CURLOPT_POST, 1);
		# Turns out you don't need to decompose and recompose ...
		#parse_str(file_get_contents("php://input"), $raw_post_array); # use raw because cooked is overcooked into arrays
		#curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($raw_post_array));
        #if ( !isset( $HTTP_RAW_POST_DATA ) ) {
        #        $HTTP_RAW_POST_DATA = file_get_contents( 'php://input' );
        #}
		$input = file_get_contents("php://input");

		$filecount=0;
		foreach ($_FILES as $k => $v) {
			if ($v['error']) continue;
			$filecount++;
		}
		if ($input && $filecount==0) {
			curl_setopt($curl, CURLOPT_POSTFIELDS, $input);
			$debuginfo.="<br>post by php://input: ".$input;
		}
		else {  /* php://input is faulty for file uploads, so hack the uploads from _FILES back to _POST: */
			foreach ($_FILES as $k => $v) {
				if ($v['error']) continue;
				$_POST[$k] = '@'.$v['tmp_name'].  ';type='.$v['type'].  ';filename='.$v['name'];
				#$debuginfo.="<br>file: $k -> ".print_r($v,1);
			}
			curl_setopt($curl, CURLOPT_POSTFIELDS, $_POST);
			#$debuginfo.="<br>post from _FILES: ".print_r($_POST,1);
		}
		#echo "<pre>input::"; echo file_get_contents("php://input"); echo "</pre>";
		#echo "<pre>POST::"; print_r($raw_post_array); echo "</pre>";
		#echo "<pre>POST::"; print_r($_POST); echo "</pre>";
		#phpinfo();

	}

	$http_reply = curl_exec($curl);
	$info = curl_getinfo($curl);
	if (!$http_reply && curl_errno($curl)) {
		report_error(curl_error($curl)); # ,"url=$url debug: $debuginfo");
	}

	$http_response_code='';
	while (1) {
		$break=strpos($http_reply,"\r\n\r\n");
		$break_len=4;
		if ($break==0) {$break=strpos($http_reply,"\n\n"); $break_len=2; }
		if ($break==0) {$break=strlen($http_reply); $break_len=0 ;}
		$reply_headers=substr($http_reply,0,$break);
		$http_body=substr($http_reply,$break+$break_len);
		if (preg_match('/^HTTP\/1.. 1[0-9][0-9]/', $reply_headers)) {
			$http_reply=$http_body;
			continue;
		}
		if (preg_match('/^(HTTP\/\S+ \d\d\d.*)/', $reply_headers, $m)) {
			$http_response_code=$m[1];
		}
		break;
		$http_reply=null;
	}

	# echo "<pre>reply_headers:: $reply_headers ::::<br></pre>";

	$content_type = $info['content_type'];
	if ($http_response_code) {
		header($http_response_code);
	}
	header('Content-Type: '.$content_type);
	foreach (explode("\n",$reply_headers) as $reply_header) {
		$reply_header=trim($reply_header);
		if (preg_match('/^Location:/i',$reply_header)) {
			$reply_header='Location: '.rewrite_url(trim(substr($reply_header,9)));
			header($reply_header);
		}
		else if (preg_match('/^(Set-Cookie):/i',$reply_header)) {
			$cookiedata=trim(substr($reply_header,strpos($reply_header,':')+1));
			$cookie_name=trim(substr($cookiedata,0,strpos($cookiedata,'=')));
			$cookie_value=trim(substr($cookiedata,strpos($cookiedata,'=')+1,65535));
			if (strpos($cookie_value,';')) {
				$cookie_value=trim(substr($cookie_value,0,strpos($cookie_value,';')));
			}
			#echo "COOKIE cookie_name=$cookie_name cookie_value=$cookie_value<br>";
			setcookie($cookie_name,urldecode($cookie_value));
			# $name=trim(substr($cookie,0,strpos($cookie,'=')));
			# setcookie('rcookie_'.$name,$cookie); # FIXME: we should set http_only too, for security
			# #echo "<pre>header:: $reply_header::<br></pre>";
			# #echo "<pre>cookie:: $cookie ::::<br></pre>";
			# #echo "<pre>name:: $name ::::<br></pre>";
			#
		}
		else if (preg_match('/^(WWW-Authenticate|Server|X-Powered-By|Expires|Last-Modified):/i',$reply_header)) {
			header($reply_header);
		}
	} # debug..  #$headers = apache_request_headers(); #foreach ($headers as $header => $value) { echo "$header: $value <br />\n"; } #phpinfo();
	#foreach ($request_headers as $header => $value) { echo "$header: $value <br />\n"; }

	if (substr($content_type,0,8)=='text/css' ) {
		#foreach (apache_request_headers() as $browser_header=>$browser_value) {
		#	echo "# $browser_header: $browser_value\n"; }
		echo rewrite_stylesheet_urls($http_body);
	}
	else if (substr($content_type,0,9)=='text/html'
		&& preg_match('/<(html|body|title)\b/i',$http_body)
		&& !preg_match('/^.{0,4}<\?xml/s',$http_body) ) {
		# It might be an idea to use this HTML parser:
		# if (file_exists(__DIR__.'/html5lib-php-0.1/library/HTML5/Parser.php')) {
		# 	require_once __DIR__.'/html5lib-php-0.1/library/HTML5/Parser.php';
		# 	$DOM = HTML5_Parser::parse($http_body);
		# }
		$prefix = '';
		# Use the HTTP content-type encoding indicator, if there is one
		if (! preg_match('/charset=([0-9A-Z_-]+)/', $content_type, $matches)) {
			$charset='UTF-8';
		}
		else {
			$charset = $matches[1];
		}
		#echo "::charset=$charset::";
		$prefix .= '<?xml encoding="'.$charset.'">';
		if (@$_GET['i']=='debugme') {
			# erm, this almost fixes the centos bug works ... must test!
			$http_body = mb_convert_encoding($http_body,  "HTML-ENTITIES", "UTF-8");
		}
		$DOM=new DOMDocument('1.0',$charset);

		# $DOM->substituteEntities = false;
		# $DOM->strictErrorChecking = false ;
		# $DOM->encoding = $charset;
		$DOM->loadHTML($prefix.$http_body);
		# $DOM->strictErrorChecking = false ;
		# $DOM->substituteEntities = false;
		# $DOM->encoding = $charset;
		# if (@$_GET['i']=='debugme') { $DOM->substituteEntities = False; }
		foreach ($DOM->childNodes as $item) {
			if ($item->nodeType == XML_PI_NODE) {
				$DOM->removeChild($item); // remove hack, so it doesn't come out again
				break;
			}
		}
		$DOM->encoding = $charset; // try to set the "proper" encoding

		tag_attribute_url_rewrite($DOM,'img','src');
		tag_attribute_url_rewrite($DOM,'script','src');
		tag_attribute_url_rewrite($DOM,'link','href');
		tag_attribute_url_rewrite($DOM,'base','href');
		tag_attribute_url_rewrite($DOM,'a','href');
		tag_attribute_url_rewrite($DOM,'area','href');
		tag_attribute_url_rewrite($DOM,'form','action');
		tag_attribute_url_rewrite($DOM,'iframe','src');
		tag_attribute_url_rewrite($DOM,'frame','src');
		tag_attribute_style_rewrite($DOM,'div','style');
		tag_attribute_meta_rewrite($DOM);  // meta refresh http-equiv=0;URL=xxx
		$items = $DOM->getElementsByTagName('style');
		for ($i = 0; $i < $items->length; $i++) {
			$node = $items->item($i);
			$src = $node->textContent;
			if (!$src) continue;
			$src=rewrite_stylesheet_urls($src);
			$node->removeChild($node->firstChild);
			$node->appendChild(new DOMText($src));
		}
		$items = $DOM->getElementsByTagName('script');
		for ($i = 0; $i < $items->length; $i++) {
			$node = $items->item($i);
			$src = $node->textContent; # BEWARE: this does not quite work: $src = $node->nodeValue;
			if (!$src) continue;
			$src=rewrite_script_urls($src);
			# BEWARE: this does not quite work: $node->nodeValue=$src;
			$node->removeChild($node->firstChild);
			$node->appendChild(new DOMText($src));
		}
		$html = $DOM->saveHTML();
		unset($DOM); # So long, and thanks for the HTML
		$previewnotice = file_get_contents('preview.html');
		global $stats;
		$stats = array();
		$stats['changes'] = substr_count($html,previewurl());
		$stats['plural'] = ( $stats['changes']==1 ? "" : "s");
		$stats['microtime'] =sprintf("%0.1f",get_execution_time());
		$stats['ip'] = $ip;
		$stats['url'] = $url;
		$stats['hostname'] = $host;
		$stats['domain'] = preg_replace('/^www\./','',$host);
		$previewnotice = preg_replace_callback('/\{\$(\w+)\}/i', 'globalvariablelookup', $previewnotice);
		$html = preg_replace(':(</body\s*>):i',$previewnotice.'$1<!-- '.$ip.' version of '.$url.' -->',$html);
		echo $html;
	}
	else {
		echo $http_body;
	}
}

require_once("config.php");
go();
