<?php
require 'sites/all/libraries/php-jwt/vendor/autoload.php';
use \Firebase\JWT\JWT;
function weixin_initinvoicelist_callback($mode){
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
          'number' =>$node->field_invoicenumber['und'][0]['value']
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
  if($nid = get_invoice_id_by_number($invoiceNumber)){
    $node = node_load($nid);
    $tids = array_column($node->field_wxuseref['und'], 'target_id');
    if(!in_array($wxuserid, $tids)){
      $node->field_wxuseref['und'][] = array('target_id' => $wxuserid);
    }
    $node->title = $invoiceTitle;

  }else{
    $node = new stdClass();
    $node->type = 'invoice';
    $node->is_new = 1;
    $node->uid = 1;
    $node->status = 1;
    $node->language = 'und';
    $node->title = $invoiceTitle;
    $node->field_invoicenumber['und'][0]['value'] = $invoiceNumber;
    $node->field_wxuseref['und'][0]['target_id'] = $wxuserid;

  }
  node_save($node);
  $return = array(
    'id' => $node->nid,
    'title'=> $node->title,
    'number'=> $invoiceNumber
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
  $node->field_invoicenumber['und'][0]['value'] = $invoice->field_invoicenumber['und'][0]['value'];
  $node->status = 1;
  node_save($node);
  $record->field_invoiceref['und'][0]['target_id'] = $node->nid;
  node_save($record);
  // field_attach_update('node', $record);
  return drupal_json_output($invoice->title);
  drupal_json_output('success');
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
  $node = node_load($nid);
  $refs = $node->field_wxuseref['und'];
  foreach ($refs as $index => $value) {
    if($refs[$index]['target_id'] = $wxuserid){
      unset($refs[$index]);
    }
  }
  $node->field_wxuseref['und'] = $refs;
  field_attach_update('node', $node);
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
          'number' =>$node->field_invoicenumber['und'][0]['value']
        );

    }
  }
  drupal_json_output($return);
}
