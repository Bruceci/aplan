<?php
function weixin_getprice_callback(){
  //$jwt = $_SERVER['HTTP_JWT']; // READY TO USE
  $query = new EntityFieldQuery();
  $result = $query->entityCondition('entity_type', 'taxonomy_term')
        ->propertyCondition('vid', '2')
        ->execute();
  $terms = entity_load('taxonomy_term', array_keys($result['taxonomy_term']));
  foreach ($terms as $key => $term) {
    $return[] = array(
      'name' =>$term->name,
      'price' => $term->field_oilprice['und'][0]['value']
    );
  }

   drupal_json_output($return);
}
