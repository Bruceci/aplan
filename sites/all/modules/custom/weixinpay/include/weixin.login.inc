<?php
require 'sites/all/libraries/php-jwt/vendor/autoload.php';
use \Firebase\JWT\JWT;
function weixin_login_callback(){
  $code = $_POST['code'];
  $aff_jwt = $_POST['aff_jwt'];
  $session = weixinpay_get_session($code);
  $openid = $session->openid;
  $aff_openid = '';
  $aff_id = '';
  if($aff_jwt){
    $decoded = JWT::decode($aff_jwt, KEY, array('HS256'));
    $aff_openid = $decode->openid;
    $aff_nid= wxuser_load_id_by_openid($aff_openid);
  }
  if($nid = wxuser_load_id_by_openid($openid)){
    $node = node_load($nid);
    $affiliated = $node->field_affiliated['und'][0]['value'];
    $affiliation = $node->field_affiliation;
    if($aff_id && !$affiliated && !$affiliation && $openid =! $aff_openid){
      $node->field_affiliation['und'][0]['target_id'] = $aff_nid;
      field_attach_update('node', $node);
    }
  }else{
    $node = new stdClass();
    $node->type = 'wx_user';
    $node->language = 'und';
    $node->uid = 1;
    $node->is_new = TRUE;
    $node->title = $openid;
    $node->field_openid['und'][0]['value'] = $openid;
    if($aff_id){
      $node->field_affiliation['und'][0]['target_id'] = $aff_nid;
    }
    node_save($node);
  }

  $jwt = jwt_sign_and_issue($node);
  drupal_json_output($jwt);

}
function weixin_user_update_callback(){
  $jwt = $_POST['jwt'];
  $decoded = JWT::decode($jwt, KEY, array('HS256'));
  $openid = $decoded->openid;
  $user = wxuser_load_by_openid($openid);
  $user->title = $_POST['nickName'];
  $user->field_city['und'][0]['value'] = $_POST['city'];
  $user->field_country['und'][0]['value'] = $_POST['country'];
  $user->field_gender['und'][0]['value'] = $_POST['gender'];
  $user->field_language['und'][0]['value'] = $_POST['language'];
  $user->field_province['und'][0]['value'] = $_POST['province'];
  $user->field_avatarurl['und'][0]['value'] = $_POST['avatarUrl'];
  field_attach_update('node', $user);
  drupal_json_output("success");
}
function jwt_sign_and_issue($wxuesr){

  $affiliated = $wxuesr->field_affiliated['und'][0]['value'];
  $affiliation = '';
  if($wxuesr->field_affiliation){
      $affiliation = $wxuesr->field_affiliation['und'][0]['target_id'];
  }
  $openid = $wxuesr->field_openid['und'][0]['value'];
  $token = array(
    'iss' => 'https://0376866.com',
    'aud' => 'https://weixin.qq.com',
    'iat' => time(),
    'affiliated' => $affiliated,
    'affiliation' => $affiliation,
    'openid' => $openid,
    'nid' => $wxuesr->nid,
    'title' => $wxuesr->title

  );
  $jwt = JWT::encode($token, KEY);
  return array(
    'jwt' => $jwt,
    'affilated' => $affiliated,
    'affiliation' => $affiliation
  );
}
