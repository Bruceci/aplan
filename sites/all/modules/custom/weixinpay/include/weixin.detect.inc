<?php
function weixin_detect_callback(){

  $ch_nozzle = variable_get('ch_nozzle', 0);
  $ch_record = variable_get('ch_record', 0);
  $ch_price = variable_get('ch_price', 0);
  $ch_wxuser =  variable_get('ch_wxuser', 0);
  drupal_json_output(array('ch_nozzle'=> $ch_nozzle, 'ch_record' => $ch_record, 'ch_price' => $ch_price, 'ch_wxuser' => $ch_wxuser));

}
