<?php
function weixinpay_wait_notify_callback(){
  $successReturn = array(
    'return_code' => 'SUCCESS',
    'return_msg' => 'OK'
  );
  $failureReturn = array(
    'return_code' => 'FAIL'
  );
  $data = FromXml($GLOBALS['HTTP_RAW_POST_DATA']);
  $sign = $data['sign'];
  unset($data['sign']);
  $newSign =  weixinpay_sign($data);
  $str = drupal_http_build_query($data);
  watchdog('weixin notify str', $str);

  if($newSign === $sign){
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
       $pay_record->field_resultcode['und'][0]['value'] = $data['result_code'];
       $pay_record->field_returncode['und'][0]['value'] = $data['return_code'];
       $pay_record->field_timend['und'][0]['value'] = format_date(strtotime($data['time_end']), 'custom', 'Y-m-d H:i:s', 'Asia/Shanghai');
       $pay_record->field_tradetype['und'][0]['value'] = $data['trade_type'];
       field_attach_update('node', $pay_record);
        echo ToXml($successReturn);
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
