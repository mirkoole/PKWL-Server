<?php
/**
* uninstall.php
* by Mirko Oleszuk
*/

/**
* This script runs when the plugin
* is uninstalled via the wordpress
* backend.
* It drops the plugins database
* tables, deletes the public key
* of all users and removes the db
* version number.
*/

// if uninstall is not called from WordPress Admin Backend
if(!defined('WP_UNINSTALL_PLUGIN')){
  exit;
}

// remove database table
global $wpdb;
$table_tlp     = $wpdb->prefix . "pkwl_tlp";
$table_primes  = $wpdb->prefix . "pkwl_primes";

$sql = "DROP TABLE IF EXISTS `$table_tlp`;";
$wpdb->query($sql);

$sql = "DROP TABLE IF EXISTS `$table_primes`;";
$wpdb->query($sql);

// remove public keys of all users
$sql = "DELETE FROM ".$wpdb->prefix."usermeta WHERE `meta_key` = 'pkwl_public_key' OR `meta_key` = 'pkwl_disable_password';";
$wpdb->query($sql);

// remove internal version number
delete_option( "pkwl_db_version" );

?>
