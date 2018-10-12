<?php
function weixin_payrecords_callback(){
  $jwt = $_SERVER['HTTP_JWT'];
  $wxuser = load_wxuser_by_jwt($jwt);
  $query = new EntityFieldQuery();
  $query->entityCondition('entity_type', 'node')
      ->entityCondition('bundle', 'pay_record')
      ->fieldCondition('field_payuser', 'target_id', $wxuser->nid)
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
    $nozzle = nozzle_load_by_number($nozzleNumber);
    $oilTypeId = $nozzle->field_oiltype['und'][0]['target_id'];
    $oilType = entity_load('taxonomy_term', array($oilTypeId));
    $oilType = reset($oilType);
    $invoiceTitle = '';
    if(!empty($record->field_invoiceref)){
      $invoicePrintId = $record->field_invoiceref['und'][0]['target_id'];
      $invoicePrint = node_load($invoicePrintId);
      $invoiceTitle = $invoicePrint->title;
    }
    $return[] = array(
      'id' => $record->nid,
      'date' => $record->field_timend['und'][0]['value'],//format_date(strtotime($record->field_timend['und'][0]['value']), 'custom', 'Y-m-d H:i:s', 'UTC'),
      'oilType' => $oilType->field_shortname['und'][0]['value'],
      'price' => $record->field_price['und'][0]['value'],
      'total' => $record->field_totalfee['und'][0]['value'],
      'nozzleNumber' => $record->field_recordnozzlenumber['und'][0]['value'],
      'outTradeNo' =>  $record->field_outradeno['und'][0]['value'],
      'invoiceTitle' => $invoiceTitle
    );

  }
  drupal_json_output($return);

}
