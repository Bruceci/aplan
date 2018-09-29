<?php
function weixinpay_wait_notify_callback(){

  $successReturn = array(
    'return_code' => 'SUCCESS',
    'return_msg' => 'OK'
  );
  $failureReturn = array(
    'return_code' => 'FAIL'
  );
  $data = FromXml(file_get_contents("php://input"));
  $str = drupal_http_build_query($data);
  watchdog('weixin notify str', $str);

  $return_code = $data['return_code'];
  $result_code = $data['result_code'];
  $out_trade_no = $data['out_trade_no'];
  $openid = $data['openid'];
  if($data['result_code'] != 'SUCCESS'){
    $err_code = $data['err_code'];
    $err_code_desc = $data['err_code_des'];
    watchdog('weixinpay notify', "$out_trade_no ($err_code $err_code_desc)", WATCHDOG_ERROR);
    if(!$data['return_code'] != 'SUCCESS'){
      $return_msg = $data['return_msg'];
      watchdog('weixinpay notify', "$out_trade_no ($return_msg)", WATCHDOG_ERROR);
      return;
    }
    return;
  }
  //$data = FromXml($GLOBALS['HTTP_RAW_POST_DATA']);
  $sign = $data['sign'];
  unset($data['sign']);
  $checkSign =  weixinpay_sign($data);
  if($checkSign === $sign){
     parse_str(urldecode($data['attach']),$attach);
     $pay_record = node_load($attach['pay_record_id']);

     if(count($pay_record->field_resultcode) && ($pay_record->field_resultcode['und'][0]['value'] === 'SUCCESS')) {
       echo ToXml($successReturn);
       return;
     }
     if($pay_record->title === $data['out_trade_no']){
       $pay_record->field_banktype['und'][0]['value'] = $data['bank_type'];
       $pay_record->field_feetype['und'][0]['value'] = $data['fee_type'];
       $pay_record->field_cashfee['und'][0]['value'] = $data['cash_fee']/100;
       $pay_record->field_totalfee['und'][0]['value'] = $data['total_fee']/100;
       $pay_record->field_isubscribe['und'][0]['value'] = $data['is_subscribe'];
       $pay_record->field_transactionid['und'][0]['value'] = $data['transaction_id'];
       $pay_record->field_resultcode['und'][0]['value'] = $result_code;
       $pay_record->field_returncode['und'][0]['value'] = $return_code;
       $pay_record->field_timend['und'][0]['value'] = format_date(strtotime($data['time_end']), 'custom', 'Y-m-d H:i:s', 'Asia/Shanghai');
       $pay_record->field_tradetype['und'][0]['value'] = $data['trade_type'];
       node_save($pay_record);
       echo ToXml($successReturn);
       weixin_pay_out($openid, $data['total_fee'], $pay_record->nid);
        return;
     }else{
        echo ToXml($failureReturn);
        return;

     }
  }else{
      echo ToXml($failureReturn);
      return;
  }

}
function weixin_pay_out($openid, $amount, $pay_record_id){
  $wxuser = wxuser_load_by_openid($openid);
  if(empty($wxuser->field_affiliation)){
     return;
  }else{
    $aff_id = $wxuser->field_affiliation['und'][0]['target_id'];
    $aff_user = node_load($aff_id);
    $aff_openid = $aff_user->field_openid['und'][0]['value'];

  }
  $rule_set = get_enable_rule_set();
  if(!$rule_set){
    return;
  }
  $rule_set = entity_metadata_wrapper('node', $rule_set);
  $start = $rule_set->field_period->value->value();
  $end = $rule_set->field_period->value2->value();
  $now = time();

  if($rule_set->field_enable->value() == 0 || $start > $now || $end < $now ){
     return;
  }
  if($rule_set->type->value() == 'pay_out_rule_a_collection') {
      $rules_id = array();
      foreach ($rule_set->field_rulearef->value() as $index => $rule) {
        $rules_id[] = $rule->nid;
      }
      if($rule_matched = weixin_load_matched_rule_by_ids($rules_id)){
        $rule_matched = entity_metadata_wrapper('node', $rule_matched);
        $commission = ($rule_matched->field_commission->value()) * 100;
        $rebate = ($rule_matched->field_rebate->value()) * 100;
        $reach_amount = ($rule_matched->field_reachamount->value()) * 100;
        if($rule_set->field_cumulative->value()){
          $multiple = floor($amount/$reach_amount);
          $commission = $commission * $multiple;
          $rebate = $rebate * $multiple;
        }
      }else{
        return;
      }
  }else if($rule_set->type->value() == 'pay_out_rule_b_collection'){
    $rules = $rule_set->field_rulebref->value();
    $rules_id = array();
    foreach ($rules as $index => $rule) {
      $rules_id[] = $rule->nid;
    }
    if($rule_matched = weixin_load_matched_rule_by_ids($rules_id, $amount)){
      $rule_matched = entity_metadata_wrapper('node', $rule_matched);
      $commission = $rule_matched->field_commissionrate->value();
      $rebate = $rule_matched->field_rebaterate->value();
      $commission = $amount * ($commission/100);
      $rebate = $amount * ($rebate/100);

    }else{
      return;
    }

  }

  weixin_pay_out_action($openid, $rebate, array('desc' => '返利 (南郊石化)', 'record_id' => $pay_record_id));
  weixin_pay_out_action($aff_openid, $commission, array('desc' => '赏金 (南郊石化)', 'record_id' => $pay_record_id));

}
function weixin_load_matched_rule_by_ids($rules_id, $amount){
  $rules = entity_load('node', $rules_id);
  $candidates = array();
  foreach ($rules as $nid => $rule) {
    $reach_amount = ($rule->field_reachamount['und'][0]['value']) * 100;
    if($amount >= $reach_amount){
      $candidates[] = array(
        $nid => $reach_amount
      );
    }
  }
  if($candidates){
    $matched = max($candidates);
    return $rules[key($matched)];
  }else{
    return false;
  }


}
function weixin_pay_out_action($openid, $amount, $info){

  $params = array(
    'mch_appid' => 'wxb6c74c1f97c5a72e',
    'mchid' => '1511838561',
    'nonce_str' => md5(drupal_random_key(32)),
    'partner_trade_no' => format_date(time(), 'custom', 'YmdHis') . 'OUT' . rand(1000, 9999),
    'openid' => $openid,
    'amount' => $amount,
    'check_name' => 'NO_CHECK',
    'desc' => $info['desc'],
    'spbill_create_ip' => '52.69.48.85'
  );

  $sign = weixinpay_sign($params);
  $params['sign'] = $sign;


  $contextOptions = array(
      'ssl' => array(
          'verify_peer' => TRUE,
          'local_cert' => '/home/ubuntu/cert/apiclient_cert.pem',
          'local_pk' => '/home/ubuntu/cert/apiclient_key.pem',
          'verify_depth' => 5,
          'allow_selt_sign' => TRUE
      )
  );

  $response = drupal_http_request(
    'https://api.mch.weixin.qq.com/mmpaymkttransfers/promotion/transfers',
    array(
      'method' => 'POST',
      'data' => ToXml($params),
      'headers' => array(
         'Content-Type' => 'application/x-www-form-urlencoded',
      ),
      'context' => stream_context_create($contextOptions)
     )
  );
  $result = FromXml($response->data);
  if($result['return_code'] == 'SUCCESS'){

    $trans = entity_create('node', array('type' => 'pay_out'));
    $trans->uid = 1;
    $trans_wrapper = entity_metadata_wrapper('node', $trans);
    $trans_wrapper->title = 'Pending';
    $trans_wrapper->field_appid = $result['mch_appid'];
    $trans_wrapper->field_mchid = $result['mchid'];
    $trans_wrapper->field_returncode = $result['return_code'];
    $trans_wrapper->field_openid->set($openid);
    $trans_wrapper->field_payrecordref = $info['record_id'];
    $trans_wrapper->field_amount->set($amount/100);
    if($result['result_code'] == 'SUCCESS'){
      $trans_wrapper->title = $result['partner_trade_no'];
      $trans_wrapper->field_resultcode = $result['result_code'];
      $trans_wrapper->field_paymentno = $result['payment_no'];
      $trans_wrapper->field_paymentime = strtotime($result['payment_time']);
    }else{
      $trans_wrapper->field_resultcode = $result['result_code'];
      $trans_wrapper->field_errcode = $result['err_code'];
    }
    $trans_wrapper->save();
  }

}
