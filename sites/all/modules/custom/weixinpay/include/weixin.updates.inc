<?php
function weixin_update_nozzle_callback(){

    $query = new EntityFieldQuery();
    $query
      ->entityCondition('entity_type', 'node')
      ->entityCondition('bundle', 'nozzle')
      ->fieldOrderBy('field_nozzlenumber','value', 'ASC');
    $result = $query->execute();
    $nids = array_keys($result['node']);
    $nozzles = entity_load('node', $nids);
    $return = array();
    foreach ($nozzles as $key => $nozzle) {
      $nozzleNumber = $nozzle->field_nozzlenumber['und'][0]['value'];
      $oilTypeId = $nozzle->field_oiltype['und'][0]['target_id'];
       $oilType = entity_load('taxonomy_term', array($oilTypeId));
       $oilType = reset($oilType);
       $oilTypeName = $oilType->name;
       $oilTypeDescription = $oilType->description;
       $return[] = array(
         'number' => $nozzleNumber,
         'type' => $oilTypeName,
         'description' => $oilTypeDescription,
       );


    }
    drupal_json_output($return);

}
