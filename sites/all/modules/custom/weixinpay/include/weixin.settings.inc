<?php
require 'sites/all/libraries/php-jwt/vendor/autoload.php';
use \Firebase\JWT\JWT;
function weixin_initinvoicelist_callback(){
  $jwt = $_SERVER['HTTP_JWT'];
  $decoded = JWT::decode($jwt, KEY, array('HS256'));
  $wxuserid = wxuser_load_id_by_openid($decoded->openid);
  $query = new EntityFieldQuery();
  $query->entityCondition('entity_type', 'node')
        ->entityCondition('bundle', 'invoice')
        ->fieldCondition('field_wxuseref', 'target_id', $wxuserid);
  $result =  $query->execute();
  $return = array();
  if(isset($result['node'])){
    $nodes = entity_load('node', array_keys($result['node']));
    foreach ($nodes as $key => $node) {
        $return[] = array(
          'id' => $node->nid,
          'title' => $node->title,
          'iTitle' => $node->field_invoicetitle['und'][0]['value'],
          'number' =>$node->field_invoicenumber['und'][0]['value']
        );

    }
  }

  drupal_json_output($return);
}
function weixin_initvehicleinfo_callback(){
  $jwt = $_SERVER['HTTP_JWT'];
  $decoded = JWT::decode($jwt, KEY, array('HS256'));
  $wxuserid = wxuser_load_id_by_openid($decoded->openid);
  $query = new EntityFieldQuery();
  $query->entityCondition('entity_type', 'node')
        ->entityCondition('bundle', 'vehicle')
        ->fieldCondition('field_wxuseref', 'target_id', $wxuserid);
  $result =  $query->execute();
  $return = array();
  if(isset($result['node'])){
    $nodes = entity_load('node', array_keys($result['node']));
    foreach ($nodes as $key => $node) {
        $return[] = array(
          'id' => $node->nid,
          'title' => $node->title,
          'licenseNumber' => $node->field_licensenumber['und'][0]['value'],
          'fuelConsumption' =>$node->field_fuelconsumption['und'][0]['value']
        );

    }
  }

  drupal_json_output($return);
}
function weixin_create_invoice(){
  $jwt = $_SERVER['HTTP_JWT'];
  $decoded = JWT::decode($jwt, KEY, array('HS256'));
  $wxuserid = wxuser_load_id_by_openid($decoded->openid);
  $invoiceTitle = $_POST['invoiceTitle'];
  $invoiceNumber = $_POST['invoiceNumber'];
  if($nid = get_invoice_id_by_number_and_wxuser($invoiceNumber, $wxuserid)){
    $node = node_load($nid);
    $node->title = $invoiceTitle;
    $node->field_invoicetitle['und'][0]['value'] = $invoiceTitle;

  }else{
    $node = new stdClass();
    $node->type = 'invoice';
    $node->is_new = 1;
    $node->uid = 1;
    $node->status = 1;
    $node->language = 'und';
    $node->title = $invoiceTitle;
    $node->field_invoicetitle['und'][0]['value'] = $invoiceTitle;
    $node->field_invoicenumber['und'][0]['value'] = $invoiceNumber;
    $node->field_wxuseref['und'][0]['target_id'] = $wxuserid;

  }
  node_save($node);
  $return = array(
    'id' => $node->nid,
    'title'=> $node->title,
    'iTitle' => $invoiceTitle,
    'number'=> $invoiceNumber
  );
  drupal_json_output($return);

}

function weixin_create_vehicle(){
  $jwt = $_SERVER['HTTP_JWT'];
  $decoded = JWT::decode($jwt, KEY, array('HS256'));
  $wxuserid = wxuser_load_id_by_openid($decoded->openid);
  $vehicleLicenseNumber = $_POST['vehicleLicenseNumber'];
  $vehicleFuelConsumption = $_POST['vehicleFuelConsumption'];
  if($nid = get_vehicle_id_by_license_and_wxuser($vehicleLicenseNumber, $wxuserid)){
    $node = node_load($nid);
    $node->field_fuelconsumption['und'][0]['value'] = $vehicleFuelConsumption;

  }else{
    $node = new stdClass();
    $node->type = 'vehicle';
    $node->is_new = 1;
    $node->uid = 1;
    $node->status = 1;
    $node->language = 'und';
    $node->title = $vehicleLicenseNumber;
    $node->field_licensenumber['und'][0]['value'] = $vehicleLicenseNumber;
    $node->field_fuelconsumption['und'][0]['value'] = $vehicleFuelConsumption;
    $node->field_wxuseref['und'][0]['target_id'] = $wxuserid;

  }
  node_save($node);
  $return = array(
    'id' => $node->nid,
    'title' => $vehicleLicenseNumber,
    'licenseNumber'=> $vehicleLicenseNumber,
    'fuelConsumption'=> $vehicleFuelConsumption
  );
  drupal_json_output($return);

}
function weixin_confirm_invoice_callback(){
  $invoiceId = $_POST['invoiceId'];
  $recordId = $_POST['recordId'];
  $invoice = node_load($invoiceId);
  $record = node_load($recordId);
  if(!empty($record->field_invoiceref)){
    drupal_json_output('');
    return;
  }
  $node = new stdClass();
  $node->type = 'invoice_print';
  $node->is_new = true;
  $node->uid = 1;
  $node->language = 'und';
  $node->title = $invoice->title;
  $node->field_invoicetitle['und'][0]['value'] = $invoice->field_invoicetitle['und'][0]['value'];
  $node->field_invoicenumber['und'][0]['value'] = $invoice->field_invoicenumber['und'][0]['value'];
  $node->status = 1;
  node_save($node);
  $record->field_invoiceref['und'][0]['target_id'] = $node->nid;
  node_save($record);
  // field_attach_update('node', $record);
  return drupal_json_output($invoice->field_invoicetitle['und'][0]['value']);
}
function weixin_confirm_vehicle_callback(){
  $vehicleId = $_POST['vehicleId'];
  $recordId = $_POST['recordId'];
  $vehicle = node_load($vehicleId);
  $record = node_load($recordId);
  if(!empty($record->field_vehicleref)){
    drupal_json_output('');
    return;
  }
  $node = new stdClass();
  $node->type = 'record_vehicle';
  $node->is_new = true;
  $node->uid = 1;
  $node->language = 'und';
  $node->title = $vehicle->title;
  $node->field_licensenumber['und'][0]['value'] = $vehicle->field_licensenumber['und'][0]['value'];
  $node->field_fuelconsumption['und'][0]['value'] = $vehicle->field_fuelconsumption['und'][0]['value'];
  $node->status = 1;
  node_save($node);
  $record->field_vehicleref['und'][0]['target_id'] = $node->nid;
  // node_save($record);
  field_attach_update('node', $record);
  return drupal_json_output(array('vehicleTitle' => $vehicle->field_licensenumber['und'][0]['value'],'vehicleFuelConsumption' => $vehicle->field_fuelconsumption['und'][0]['value']));
}
function get_invoice_id_by_number($invoiceNumber){
    $query = new EntityFieldQuery();
    $query->entityCondition('entity_type', 'node')
          ->entityCondition('bundle', 'invoice')
          ->fieldCondition('field_invoicenumber', 'value', $invoiceNumber);
    $result = $query->execute();
    $nid = '';
    if(isset($result['node'])){
      $nid= array_keys($result['node']);
      $nid = reset($nid);
    }
    return $nid;
}
function get_vehicle_id_by_license_and_wxuser($vehicleLicenseNumber, $wxuserid){
    $query = new EntityFieldQuery();
    $query->entityCondition('entity_type', 'node')
          ->entityCondition('bundle', 'vehicle')
          ->fieldCondition('field_licensenumber', 'value', $vehicleLicenseNumber)
          ->fieldCondition('field_wxuseref', 'target_id', $wxuserid);
    $result = $query->execute();
    $nid = '';
    if(isset($result['node'])){
      $nid= array_keys($result['node']);
      $nid = reset($nid);
    }
    return $nid;
}
function get_invoice_id_by_number_and_wxuser($invoiceNumber, $wxuserid){
    $query = new EntityFieldQuery();
    $query->entityCondition('entity_type', 'node')
          ->entityCondition('bundle', 'invoice')
          ->fieldCondition('field_invoicenumber', 'value', $invoiceNumber)
          ->fieldCondition('field_wxuseref', 'target_id', $wxuserid);
    $result = $query->execute();
    $nid = '';
    if(isset($result['node'])){
      $nid= array_keys($result['node']);
      $nid = reset($nid);
    }
    return $nid;
}
function load_invoice_by_number($invoiceNumber){
  $nid = get_invoice_id_by_number($invoiceNumber);
  $node = '';
  if($nid){
    $node = node_load($nid);
  }
  return $node;
}
function weixin_delete_invoice(){
  $jwt = $_SERVER['HTTP_JWT'];
  $decoded = JWT::decode($jwt, KEY, array('HS256'));
  $wxuserid = wxuser_load_id_by_openid($decoded->openid);
  $nid = $_POST['id'];
  node_delete($nid);
  $query = new EntityFieldQuery();
  $query->entityCondition('entity_type', 'node')
        ->entityCondition('bundle', 'invoice')
        ->fieldCondition('field_wxuseref', 'target_id', $wxuserid);
  $result =  $query->execute();
  $return = array();
  if(isset($result['node'])){
    $nodes = entity_load('node', array_keys($result['node']));
    foreach ($nodes as $key => $node) {
        $return[] = array(
          'id' => $node->nid,
          'title' => $node->title,
          'iTitle' => $node->field_invoicetitle['und'][0]['value'],
          'number' =>$node->field_invoicenumber['und'][0]['value']
        );

    }
  }
  drupal_json_output($return);
}
function weixin_delete_vehicle(){
  $jwt = $_SERVER['HTTP_JWT'];
  $decoded = JWT::decode($jwt, KEY, array('HS256'));
  $wxuserid = wxuser_load_id_by_openid($decoded->openid);
  $nid = $_POST['id'];
  node_delete($nid);
  $query = new EntityFieldQuery();
  $query->entityCondition('entity_type', 'node')
        ->entityCondition('bundle', 'vehicle')
        ->fieldCondition('field_wxuseref', 'target_id', $wxuserid);
  $result =  $query->execute();
  $return = array();
  if(isset($result['node'])){
    $nodes = entity_load('node', array_keys($result['node']));
    foreach ($nodes as $key => $node) {
        $return[] = array(
          'id' => $node->nid,
          'title' => $node->title,
          'licenseNumber' => $node->field_licensenumber['und'][0]['value'],
          'fuelConsumption' =>$node->field_fuelconsumption['und'][0]['value']
        );

    }
  }
  drupal_json_output($return);
}
