<?php
require 'sites/all/libraries/php-jwt/vendor/autoload.php';
use \Firebase\JWT\JWT;
function weixin_payrecords_callback(){
  $jwt = $_POST['jwt'];
  $decoded = JWT::decode($jwt, KEY, array('HS256'));
  $wxuserid = wxuser_load_id_by_openid($decoded->openid);
  $query = new EntityFieldQuery();
  $query->entityCondition('entity_type', 'node')
      ->entityCondition('bundle', 'pay_record')
      ->fieldCondition('field_payuser', 'target_id', $wxuserid)
      ->fieldCondition('field_resultcode', 'value', 'SUCCESS')
      ->fieldOrderBy('field_timend', 'value', 'DESC');
  $result = $query->execute();
  $return = array();
  if(!isset($result['node'])){
    drupal_json_output($return);
    return;
  }
  $nids = array_keys($result['node']);
  $records = entity_load('node', $nids);

  foreach ($records as $nid => $record) {
    $nozzleNumber = $record->field_recordnozzlenumber['und'][0]['value'];
    $nozzle = node_load($nozzleNumber);
    $oilTypeId = $nozzle->field_oiltype['und'][0]['target_id'];
    $oilType = entity_load('taxonomy_term', array($oilTypeId));
    $oilType = reset($oilType);

    $return[] = array(
      'date' => format_date(strtotime($record->field_timend['und'][0]['value']), 'custom', 'Y-m-d', 'Asia/Shanghai'),
      'oilType' => $oilType->field_shortname['und'][0]['value'],
      'price' => $record->field_price['und'][0]['value'],
      'total' => $record->field_totalfee['und'][0]['value']
    );

  }

  drupal_json_output($return);

}
