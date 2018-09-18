<?php
function wxuser_load_by_openid($openid){
  $nid = wxuser_load_id_by_openid($openid);
  $account = node_load($nid);
  return $account;
}
function wxuser_load_id_by_openid($openid){
  $query = new EntityFieldQuery();
  $query
    ->entityCondition('entity_type', 'node')
    ->entityCondition('bundle', 'wx_user')
    ->fieldCondition('field_openid', 'value', $openid);
  if($result = $query->execute()){
    $nids = array_keys($result['node']);
    return reset($nids);
  }else{
    return FALSE;
  }

}
function nozzle_load_by_number($number){
  $nid = nozzle_load_id_by_number($number);
  if($nid){
    $account = node_load($nid);
    return $account;
  }else{
    return FALSE;
  }

}
function nozzle_load_id_by_number($number){
  $query = new EntityFieldQuery();
  $query
  ->entityCondition('entity_type', 'node')
  ->entityCondition('bundle', 'nozzle')
  ->fieldCondition('field_nozzlenumber', 'value', $number);
  if($result = $query->execute()){
    $nids = array_keys($result['node']);
    return reset($nids);
  }else{
    return FALSE;
  }

}
