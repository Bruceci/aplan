<?php
function weixin_payrecords_callback(){
  $jwt = $_SERVER['HTTP_JWT'];
  $wxuser = load_wxuser_by_jwt($jwt);
  $query = new EntityFieldQuery();
  $query->entityCondition('entity_type', 'node')
      ->entityCondition('bundle', array('pay_record','manual_record'), 'IN')
      ->fieldCondition('field_payuser', 'target_id', $wxuser->nid)
      // ->fieldCondition('field_resultcode', 'value', 'SUCCESS')
      ->fieldOrderBy('field_timend', 'value', 'DESC');
  $result = $query->execute();
  $return = array();
  if(!isset($result['node'])){
    drupal_json_output($return);
    return;
  }
  $nids = array_keys($result['node']);
  $records = entity_load('node', $nids);
  $records = array_filter($records, 'filter_success_record');
  $preMeterMile = 0;


  foreach ($records as $nid => $record) {


    $invoiceTitle = '';
    $vehicleTitle = '';
    $vehicleFuelConsumption = '';
    $outTradeNo = '';
    $remark = '';
    $mileage = 0;
    $meterMile = 0;
    if($record->type == 'pay_record'){
      $outTradeNo = substr_replace($record->field_outradeno['und'][0]['value'], ' ', 6, 0);
    }
    if(!empty($record->field_invoiceref)){
      $invoicePrintId = $record->field_invoiceref['und'][0]['target_id'];
      $invoicePrint = node_load($invoicePrintId);
      $invoiceTitle = $invoicePrint->title;
    }
    if(!empty($record->field_vehicleref)){
      $vehicleId = $record->field_vehicleref['und'][0]['target_id'];
      $vehicle = node_load($vehicleId);
      $vehicleTitle = $vehicle->title;
      $vehicleFuelConsumption = $vehicle->field_fuelconsumption['und'][0]['value'];
    }
    if(!empty($record->field_metadata)){
      $metadataId = $record->field_metadata['und'][0]['target_id'];
      $metadata = reset(entity_load('record_metadata', array($metadataId)));
      if(!empty($metadata->field_metermile)){
        $meterMile = $metadata->field_metermile['und'][0]['value'];
        if($preMeterMile){
          $mileage = $preMeterMile - $meterMile;
        }
        $preMeterMile = $meterMile;
      }else{


        $preMeterMile = $meterMile;
      }
      if(!empty($metadata->field_remark)){
        $remark = $metadata->field_remark['und'][0]['value'];
      }
    }else{


       $preMeterMile = $meterMile;
    }
    $return[] = array(
      'type' => $record->type,
      'id' => $record->nid,
      'date' => $record->field_timend['und'][0]['value'],//format_date(strtotime($record->field_timend['und'][0]['value']), 'custom', 'Y-m-d H:i:s', 'UTC'),
      'fuelType' => $record->field_fueltype['und'][0]['value'],
      'price' => $record->field_price['und'][0]['value'],
      'total' => $record->field_totalfee['und'][0]['value'],
      'outTradeNo' =>  $outTradeNo,
      'invoiceTitle' => $invoiceTitle,
      'vehicleTitle' => $vehicleTitle,
      'vehicleFuelConsumption' => $vehicleFuelConsumption,
      'chargeAmount' => round($record->field_totalfee['und'][0]['value']/$record->field_price['und'][0]['value'], 2),
      'vehicleIndex' => 0,
      'invoiceIndex' => 0,
      'meterMile' => intval($meterMile),
      'mileage' => $mileage,
      'remark' => $remark
    );

  }
  drupal_json_output($return);

}

function manual_record_submit_callback(){
  $jwt = $_SERVER['HTTP_JWT'];
  $wxuser = load_wxuser_by_jwt($jwt);
  $manDate = format_date(strtotime($_POST['manDate']), 'custom', 'Y-m-d H:i:s', 'UTC');
  $manCity = $_POST['manCity'];
  $manStation = $_POST['manStation'];
  $manVehicleId = $_POST['manVehicleId'];
  $vehicle = node_load($manVehicleId);
  $recordVehicle = load_record_vehicle_by_license($vehicle->field_licensenumber['und'][0]['value']);
  if(!$recordVehicle){
    $recordVehicle = clone_vehicle_to_record_vehicle($vehicle);
  }
  $manFuelType = $_POST['manFuelType'];
  $manTotalFee = $_POST['manTotalFee'];
  $manPrice = $_POST['manPrice'];

  $record = new stdClass();
  $record->type = 'manual_record';
  $record->is_new = 1;
  $record->status = 1;
  $record->language = 'und';
  $record->uid = 1;
  $record->title = "Manual ${manStation}";
  $record->field_timend['und'][0]['value'] = $manDate;
  $record->field_fueltype['und'][0]['value'] = $manFuelType;
  $record->field_totalfee['und'][0]['value'] = $manTotalFee;
  $record->field_price['und'][0]['value'] = $manPrice;
  $record->field_vehicleref['und'][0]['target_id'] = $recordVehicle->nid;
  $record->field_payuser['und'][0]['target_id'] = $wxuser->nid;
  node_save($record);

}
function filter_success_record($record){
  if($record->type == 'manual_record'){
    return true;
  }else{
    if(!empty($record->field_resultcode) && !empty($record->field_returncode)){
      if($record->field_resultcode['und'][0]['value'] == 'SUCCESS' && $record->field_returncode['und'][0]['value'] == 'SUCCESS'){
        return true;
      }
    }
  }
  return false;

}
function metermile_submit_callback(){
  $jwt = $_SERVER['HTTP_JWT'];
  $wxuser = load_wxuser_by_jwt($jwt);
  $recordId = $_POST['recordId'];
  $record = node_load($recordId);
  $meterMile = $_POST['meterMile'];
  if(!empty($record->field_metadata)){
    $metadataId = $record->field_metadata['und'][0]['target_id'];
    $metadata = reset(entity_load('record_metadata', array($metadataId)));
    $metadata->field_metermile['und'][0]['value'] = $meterMile;
    field_attach_update('record_metadata', $metadata);
  }else{
    $metadata = new stdClass();
    $metadata->uid = 1;
    $metadata->type = 'record_metadata';
    $metadata->is_new = 1;
    $metadata->language = 'und';
    $metadata->title = $record->title;
    $metadata->field_metermile['und'][0]['value'] = $meterMile;
    entity_save('record_metadata', $metadata);
    $id = $metadata->id;
    $record->field_metadata['und'][0]['target_id'] = $id;
    field_attach_update('node', $record);
  }
  module_invoke('weixinpay', 'node_update', $record);

  drupal_json_output('success');

}
