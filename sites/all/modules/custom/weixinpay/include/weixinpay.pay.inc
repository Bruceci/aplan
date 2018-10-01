<?php
require 'sites/all/libraries/php-jwt/vendor/autoload.php';
use \Firebase\JWT\JWT;
function weixinpay_checkout_pay_callback(){
  $jwt = $_POST['jwt'];
  $nozzleNumber = $_POST['nozzle'];
  $decoded = JWT::decode($jwt, KEY, array('HS256'));
  $total_fee_yuan = $_POST['amount'];
  $total_fee = $total_fee_yuan * 100;
  $openid = $decoded->openid;
  $nonce_str = md5(drupal_random_key(32));
  $body = "南郊加油站加油${total_fee_yuan}元";

  //准备数据调用统一下单接口 获取prepay_id
  $params = array(
    'appid' => APPID,
    'mch_id' => MCH_ID,
    'nonce_str' => $nonce_str,
    'body' => $body,
    'out_trade_no' => format_date(time(), 'custom', 'YmdHis') . '_' . rand(1000, 9999),
    'total_fee' => $total_fee,
    'spbill_create_ip' => '127.0.0.1',
    'notify_url' => variable_get('notify_url'),
    'trade_type' => 'JSAPI',
    'product_id' => '1',
    'openid' => $openid,
  );
  $wxuser_nid = wxuser_load_id_by_openid($openid);
  $nozzle = nozzle_load_by_number($nozzleNumber);
  if(!$nozzle){
    echo 0;
    return;
  }
  $oilType = entity_load('taxonomy_term', array($nozzle->field_oiltype['und'][0]['target_id']));
  $oilType = reset($oilType);
  $price = $oilType->field_oilprice['und'][0]['value'];

  $new_array = array_intersect_key($params, array(
    'out_trade_no' => '',
    'appid' => '',
    'mch_id' => '',
    'total_fee' => '',
    'trade_type' => ''
  ));
  extract($new_array);
  $pay_record = new StdClass();
  $pay_record->type = 'pay_record';
  node_object_prepare($pay_record);
  $pay_record->is_new = TRUE;

  $pay_record->language = 'und';
  $pay_record->uid = 1;
  $pay_record->title = 'Pending';
  $pay_record->field_outradeno['und'][0]['value'] = $out_trade_no;
  $pay_record->field_appid['und'][0]['value'] = $appid;
  $pay_record->field_mchid['und'][0]['value'] = $mch_id;
  $pay_record->field_totalfee['und'][0]['value'] = $total_fee/100;
  $pay_record->field_payuser['und'][0]['target_id'] = $wxuser_nid;
  $pay_record->field_recordnozzlenumber['und'][0]['value'] = $nozzleNumber;
  $pay_record->field_price['und'][0]['value'] = $price;
  node_save($pay_record);
  $pay_reord_id = $pay_record->nid;
  $params['attach'] = urlencode("pay_record_id=$pay_reord_id");
  $sign_string = weixinpay_sign($params);
  $params['sign'] = $sign_string;
  $prepay_id = weixinpay_get_prepay_id($params);

  //准备返回数据给小程序客户端
  $return = array(
    'appId' => APPID,
    'timeStamp' => '' . time(),
    'nonceStr' => md5(drupal_random_key(32)),
    'package' => "prepay_id=$prepay_id",
    'signType' => 'MD5',
  );
  $return['paySign'] = weixinpay_sign($return);

  return drupal_json_output($return);
}
