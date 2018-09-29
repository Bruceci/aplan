<?php
require 'sites/all/libraries/php-jwt/vendor/autoload.php';
use \Firebase\JWT\JWT;
function weixin_login_callback(){
  $code = $_POST['code'];
  $c_jwt = $_POST['c_jwt'];
  $session = weixinpay_get_session($code);
  $openid = $session->openid;
  $nid = wxuser_load_id_by_openid($openid);
  if($nid != FALSE){
    if($c_jwt){
      drupal_json_output(array('jwt' => $c_jwt));
      return;
    }
    $node = node_load($nid);
  }else{
    $node = new stdClass();
    $node->type = 'wx_user';
    $node->language = 'und';
    $node->uid = 1;
    $node->is_new = TRUE;
    $node->title = $openid;
    $node->field_openid['und'][0]['value'] = $openid;
    node_save($node);
  }

  $jwt = jwt_sign_and_issue($node);
  drupal_json_output(array('jwt' => $jwt));

}
function weixin_setaff_callback(){
  $jwt = $_POST['jwt'];
  $decoded = JWT::decode($jwt, KEY, array('HS256'));
  $openid = $decoded->openid;
  $user = wxuser_load_by_openid($openid);
  if($user->field_affiliated['und'][0]['value'] || $user->field_affiliation){
    return;
  }

  $aff_jwt = $_POST['aff_jwt'];
  $decoded_aff = JWT::decode($aff_jwt, KEY, array('HS256'));
  $openid_aff = $decoded_aff->openid;
  $user_aff = wxuser_load_by_openid($openid_aff);
  $user->field_affiliation['und'][0]['target_id'] = $user_aff->nid;
  field_attach_update('node', $user);
  drupal_json_output('success');
}
function weixin_user_update_callback(){
  $jwt = $_POST['jwt'];
  $decoded = JWT::decode($jwt, KEY, array('HS256'));
  $openid = $decoded->openid;
  $user = wxuser_load_by_openid($openid);
  watchdog('weixin nickname', $_POST['nickName']);
  $user->title = $_POST['nickName'];
  $user->field_city['und'][0]['value'] = $_POST['city'];
  $user->field_country['und'][0]['value'] = $_POST['country'];
  $user->field_gender['und'][0]['value'] = $_POST['gender'];
  $user->field_language['und'][0]['value'] = $_POST['language'];
  $user->field_province['und'][0]['value'] = $_POST['province'];
  $user->field_avatarurl['und'][0]['value'] = $_POST['avatarUrl'];
  node_save($user);
  drupal_json_output("success");
}
function jwt_sign_and_issue($wxuesr){

  $affiliated = $wxuesr->field_affiliated['und'][0]['value'];
  $affiliation = '';
  if(isset($wxuesr->field_affiliation) && $wxuesr->field_affiliation){
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
  return $jwt;
}
