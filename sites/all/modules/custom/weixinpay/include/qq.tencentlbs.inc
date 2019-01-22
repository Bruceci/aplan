<?php
function get_current_city_callback($location){
   //$location =  '32.099317,114.069972';

     // $city = '';
  // $queryString = drupal_http_build_query(array('location' => $location, 'key' => TENCENT_LBS_KEY));
  // $response = drupal_http_request(
  //   TENCENT_LBS_GEOCODER_URL . "?$queryString"
  // );
  // $decoded = drupal_json_decode($response->data);
  // if($decoded['status'] == 0){
  //   $city = $decoded['result']['address_component'];
  // }
  $stations = '';
  $queryString = drupal_http_build_query(array('keyword' => '加油站,石化', 'filter'=>'category=加油站', 'boundary'=>'nearby(' . $location . ',1000)', 'page_size'=> '20', 'orderby' => '_distance', 'key' => TENCENT_LBS_KEY));
  $response = drupal_http_request(
    TENCENT_LBS_PLACE_URL . "?$queryString"
  );
  $decoded = drupal_json_decode($response->data);
  if($decoded['status'] == 0){
    $stations = $decoded['data'];
    foreach ($stations as $index => &$station) {
      $distance = $station['_distance'];
      $distance =  ($distance / 1000) < 1 ?  $distance . '米 ' : round($distance / 1000, 2). '公里 ';

      $station['fullTitle'] =  $distance . $station['title'];
    }
  }

  drupal_json_output($stations);

}
