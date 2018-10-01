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
  ->fieldCondition('field_nozzlenumber', 'value', $number)
  ->propertyCondition('status', 1);
  if($result = $query->execute()){
    $nids = array_keys($result['node']);
    return reset($nids);
  }else{
    return FALSE;
  }

}

function get_enable_rule_set(){
  $usable_rule_sets = array('pay_out_rule_a_collection', 'pay_out_rule_b_collection');
  $rule_sets = get_all_enable_rule_sets($usable_rule_sets);
  if(!empty($rule_sets)){
      return reset($rule_sets);
  }
  return FALSE;
}
function get_all_enable_rule_sets($usable_rule_sets){
  $query = new EntityFieldQuery();
  $stub = $query->entityCondition('entity_type', 'node')
        ->entityCondition('bundle', $usable_rule_sets, 'IN')
        ->fieldCondition('field_enable', 'value', 1)
        ->execute();
  return entity_load('node', array_keys($stub['node']));

}
