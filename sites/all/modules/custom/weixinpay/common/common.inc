<?php
require 'sites/all/libraries/php-jwt/vendor/autoload.php';
use \Firebase\JWT\JWT;
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
function JWT_decode_openid($jwt){


}
function load_wxuser_by_jwt($jwt){
    try{
      $decoded = JWT::decode($jwt, KEY, array('HS256'));
    }catch(Exception $e){
      return false;
    }
    $openid = $decoded->openid;
    if($wxuser = wxuser_load_by_openid($openid)){
      return $wxuser;
    }else{
      return false;
    }

}
function get_openid_by_jwt($jwt){
  try{
    $decoded = JWT::decode($jwt, KEY, array('HS256'));
  }catch(Exception $e){

    return false;
  }

  $openid = $decoded->openid;
  return $openid;
}
function wxuser_exsits($openid){
  $query = new EntityFieldQuery();
  $query->entityCondition('entity_type', 'node')
        ->entityCondition('bundle', 'wx_user')
        ->fieldCondition('field_openid', 'value', $openid)
        ->propertyCondition('status', 1);
  $result = $query->execute();
  if(isset($result['node'])){
    return true;
  }else{
    return false;
  }

}
function create_wxuser_by_openid($openid){
  $node = new stdClass();
  $node->type = 'wx_user';
  $node->language = 'und';
  $node->uid = 1;
  $node->is_new = TRUE;
  $node->title = $openid;
  $node->field_openid['und'][0]['value'] = $openid;
  node_save($node);
  return $node;
}
function weixin_request_callback_wrapper(){
  $jwt = isset($_SERVER['HTTP_JWT'])? $_SERVER['HTTP_JWT'] : '';
  if($jwt){
       if(!$openid =  get_openid_by_jwt($jwt)){
       drupal_add_http_header('Auth_Err', 1);
       return drupal_json_output('Jwt_parse_error');
     }
     if(!wxuser_exsits($openid)){
       create_wxuser_by_openid($openid);
     }
     drupal_add_http_header('Auth_Err', 0);
  }
  $arguments = func_get_args();
  $callback =  array_shift($arguments);
  return call_user_func($callback, ...$arguments);
}
