<?php
function weixinpay_get_session($js_code){

  $query = array(
    'js_code' => $js_code,
    'appid' => APPID,
    'secret' => SECRET,
    'grant_type' => 'authorization_code'
  );
  $queryString = http_build_query($query);
  $wxResponse =  drupal_http_request(
   SESSION_API . "?$queryString",
   array(
      'method' => 'GET'
    )
  );

  $wxSession = json_decode($wxResponse->data);
  return $wxSession;

}
function weixinpay_get_prepay_id($params){
  $weixinPayResponse = drupal_http_request(UNIFIED_API,array(
    'method' => 'POST',
    'data' => ToXml($params),
    'headers' => array(
       'Content-Type' => 'application/x-www-form-urlencoded',
    ),
  ));

  $data = FromXml($weixinPayResponse->data);
  watchdog('weixin', http_build_query($data));
  return $data['prepay_id'];
}


function weixinpay_sign($params){
  ksort($params);
  $string = ToUrlParams($params);
  $string = $string  . '&key=' . MCH_KEY;
  $string = md5($string);
  $result = strtoupper($string);
  return $result;
}
 function ToXml($php_array)
{


    $xml = "<xml>";
    foreach ($php_array as $key=>$val)
    {
      if (is_numeric($val)){
        $xml.="<".$key.">".$val."</".$key.">";
      }else{
        $xml.="<".$key."><![CDATA[".$val."]]></".$key.">";
      }
      }
      $xml.="</xml>";
      return $xml;
}
function ToUrlParams($params)
{
  $buff = "";
  foreach ($params as $k => $v)
  {
    if($k != "sign" && $v != "" && !is_array($v)){
      $buff .= $k . "=" . $v . "&";
    }
  }

  $buff = trim($buff, "&");
  return $buff;
}
function FromXml($xml)
{
      libxml_disable_entity_loader(true);
      $obj= json_decode(json_encode(simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA)), true);
  return $obj;
}
