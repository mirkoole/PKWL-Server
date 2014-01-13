<?php
/**
* Plugin Name: Public-Key-Web-Login (PKWL)
* Plugin URI: http://www.codepunks.net/pkwl
* Description: A password-free login with Public-Key-Cryptography.
* Version: 0.13
* Author: Mirko Oleszuk
* Author URI: http://www.codepunks.net/pkwl
* License: The MIT License (MIT)
*/

/**
* Register wordpress events to plugin functions
*/

// function to be called on installation
register_activation_hook( __FILE__, 'pkwl_install' );

// function to be called at users profile page
add_action('show_user_profile', 'pkwl_show_options');

// function to be called when a user updates his profile
add_action('personal_options_update', 'pkwl_update_options');

// function to be called at init process of wordpress (at every page request)
add_action('init', 'pkwl_wordpress_init');


/**
* Includes
*/
include 'RSA.class.php';


/**
* Database Version Number (used for database structure upgrades)
*/
global $pkwl_db_version;
$pkwl_db_version = "0.13";


/**
* find primes
*/
function pkwl_findPrimes($numprimes){

  // check parameter
  if(!is_numeric($numprimes) || $numprimes < 1){
    return false;
  }

  global $wpdb;
  $table_primes = $wpdb->prefix . "pkwl_primes";

  // range to search for primes
  // if you increase the range, make sure to increase the database table fields
  $min = 1000000000;
  $max = 9999999999;
  $sql = 'INSERT IGNORE INTO `'.$table_primes.'` (`prime`) VALUES ';

  // search for primes
  for($i = 0; $i < $numprimes; $i++){

    // get random number
    $rand = mt_rand($min, $max);

    // find next prime
    $prime = gmp_nextprime($rand);

    // prime to string
    $prime = gmp_strval($prime);

    // build query the ugly way
    $sql .= "($prime),";
  }

  // remove trailing comma
  $sql = substr($sql, 0, strlen($sql) - 1);

  // query
  $wpdb->query($sql);

}


/**
* Adds required database tables:
*   PREFIX_pkwl_tlp ( username[60], tlp[30], n[30], timestamp[10] )
*   PREFIX_pkwl_primes ( prime[10] )
*/
function pkwl_install(){

  // check requirements
  if( !function_exists("gmp_init") ){
    exit("ERROR: PHP extension 'GMP' is missing. Please install and enable it.");
  }

  // prepare database table names
  global $wpdb;
  global $pkwl_db_version;
  $table_tlp      = $wpdb->prefix . "pkwl_tlp";
  $table_primes   = $wpdb->prefix . "pkwl_primes";

  // create table for time lock puzzles
  $sql = "CREATE TABLE IF NOT EXISTS `$table_tlp` (
            `username`  varchar(60) NOT NULL,
            `solution`  varchar(30) NOT NULL,
            `n`         varchar(30) NOT NULL,
            `timestamp` int(10)     NOT NULL,
            PRIMARY KEY (`username`)
          );";
  $wpdb->query($sql);

  // create table for primes
  $sql = "CREATE TABLE IF NOT EXISTS `$table_primes` (
            `prime` varchar(10) NOT NULL,
            PRIMARY KEY (`prime`)
          );";
  $wpdb->query($sql);

  // database version number
  add_option( "pkwl_db_version", $pkwl_db_version );

  // find primes
  pkwl_findPrimes(1000);
}


/**
* pkwl_wp_set_auth_cookie() based on the wordpress function wp_set_auth_cookie()
* does NOT set the cookies, but returns cookie contents
* @return string contains content of cookies to set
*/
function pkwl_wp_set_auth_cookie($user_id, $remember = false, $secure = ''){
  if ( $remember ) {
    $expiration = $expire = time() + apply_filters('auth_cookie_expiration', 14 * DAY_IN_SECONDS, $user_id, $remember);
  } else {
    $expiration = time() + apply_filters('auth_cookie_expiration', 2 * DAY_IN_SECONDS, $user_id, $remember);
    $expire = 0;
  }

  if ( '' === $secure )
    $secure = is_ssl();

  $secure = apply_filters('secure_auth_cookie', $secure, $user_id);
  $secure_logged_in_cookie = apply_filters('secure_logged_in_cookie', false, $user_id, $secure);

  if ( $secure ) {
    $auth_cookie_name = SECURE_AUTH_COOKIE;
    $scheme = 'secure_auth';
  } else {
    $auth_cookie_name = AUTH_COOKIE;
    $scheme = 'auth';
  }

  $auth_cookie = wp_generate_auth_cookie($user_id, $expiration, $scheme);
  $logged_in_cookie = wp_generate_auth_cookie($user_id, $expiration, 'logged_in');

  do_action('set_auth_cookie', $auth_cookie, $expire, $expiration, $user_id, $scheme);
  do_action('set_logged_in_cookie', $logged_in_cookie, $expire, $expiration, $user_id, 'logged_in');


  $cookies = "";

  $cookies .= $_SERVER['HTTP_HOST'].",".$auth_cookie_name.",".$auth_cookie.",".PLUGINS_COOKIE_PATH.",".$expire.";";
  #setcookie($auth_cookie_name, $auth_cookie, $expire, PLUGINS_COOKIE_PATH, COOKIE_DOMAIN, $secure, true);

  $cookies .= $_SERVER['HTTP_HOST'].",".$auth_cookie_name.",".$auth_cookie.",".ADMIN_COOKIE_PATH.",".$expire.";";
  #setcookie($auth_cookie_name, $auth_cookie, $expire, ADMIN_COOKIE_PATH, COOKIE_DOMAIN, $secure, true);

  $cookies .= $_SERVER['HTTP_HOST'].",".LOGGED_IN_COOKIE.",".$logged_in_cookie.",".COOKIEPATH.",".$expire.";";
  #setcookie(LOGGED_IN_COOKIE, $logged_in_cookie, $expire, COOKIEPATH, COOKIE_DOMAIN, $secure_logged_in_cookie, true);

  if ( COOKIEPATH != SITECOOKIEPATH ){
    $cookies .= $_SERVER['HTTP_HOST'].",".LOGGED_IN_COOKIE.",".$logged_in_cookie.",".SITECOOKIEPATH.",".$expire.";";
    #setcookie(LOGGED_IN_COOKIE, $logged_in_cookie, $expire, SITECOOKIEPATH, COOKIE_DOMAIN, $secure_logged_in_cookie, true);
  }

  return $cookies;
}



/**
* Listen for post data
*/
function pkwl_wordpress_init(){

  // init database tables
  global $wpdb;
  $table_tlp      = $wpdb->prefix . "pkwl_tlp";
  $table_primes   = $wpdb->prefix . "pkwl_primes";
  $table_users    = $wpdb->prefix . "users";
  $table_usermeta = $wpdb->prefix . "usermeta";

  /**
  * Auth Request received
  * check user, create time lock puzzle, save it to DB and print it the user
  */
  if(isset($_POST["pkwl_action"]) && isset($_POST["pkwl_username"]) && !isset($_POST["pkwl_solution"])){

    // set parameter for tlp generation
    $username   = $_POST["pkwl_username"];
    $action     = $_POST["pkwl_action"];
    $time       = time();

    // check parameter
    if($action != "auth") exit("ERROR-INVALID-ACTION");

    // wdpdb->prepare() escapes evil input
    // query username and public-key
    $sql = $wpdb->prepare(
      "SELECT `$table_usermeta`.`meta_value`
      FROM `$table_users`, `$table_usermeta`
      WHERE `user_login` = '%s'
      AND `$table_users`.`ID` = `$table_usermeta`.`user_id`
      AND `meta_key` = 'pkwl_public_key'
      LIMIT 0,1",
      $username
    );
    $select_result = $wpdb->get_row( $sql );

    // result = 1 means, we have exactly one user
    if($select_result != 1) exit("ERROR-INVALID-USER");

    // check if the user has uploaded a key
    $public_key = $select_result->meta_value;
    if($public_key == NULL || $public_key == "") exit("ERROR-NO-PUBLICKEY");


    /**
    * Time Lock Puzzle
    */
    // check if there is already a TLP, else generate a new one
    $sql = $wpdb->prepare(
            "SELECT `n`, `timestamp` FROM `$table_tlp` WHERE `username` = '%s';",
            $username
          );
    $select_result = $wpdb->get_row($sql);

    // set time slot var
    $t = 500000;

    // if no tlp exists or is expired, create a new one
    if($select_result == null || ($time - $select_result->timestamp) > 60){

      // query p and q
      $sql = "SELECT `prime` FROM `$table_primes` ORDER BY RAND() LIMIT 0,2";

      $p = $wpdb->get_row($sql, ARRAY_N, 0);
      $q = $wpdb->get_row($sql, ARRAY_N, 1);

      $p = $p[0];
      $q = $q[0];

      // calc tlp solution
      $n        = gmp_mul($p, $q);
      $phi      = gmp_mul(gmp_sub($p, 1), gmp_sub($q, 1));
      $solution = gmp_strval(gmp_powm(2, gmp_powm(2, $t, $phi), $n));

      // convert n to string
      $n = gmp_strval($n);

      // insert tlp or update an existing entry
      $sql = $wpdb->prepare(
        "INSERT INTO `$table_tlp`
          (`username`, `solution`, `n`, `timestamp`)
        VALUES
          ('%s', '%s', '%s', '%s')
          ON DUPLICATE KEY UPDATE
          `solution` = '%s',
          `n` = '%s',
          `timestamp` = '%s';",
        $username,
        $solution,
        $n,
        $time,
        $solution,
        $n,
        $time
      );
      $wpdb->query($sql);

    } else {

      // get tlp from db
      $n    = $select_result->n;
      $time = $select_result->timestamp;

    }

    // print puzzle to client
    echo $n . ";" . $t;

    // and we're done. we use 'exit' to stop wordpress from displaying any content
    exit;
  }


  /**
  * TLP solution received
  * check action, check user, check public-key, check tlp solution
  */
  if(  isset($_POST["pkwl_action"])
    && isset($_POST["pkwl_username"])
    && isset($_POST['pkwl_solution'])
  ) {

    // set parameters
    $action     = $_POST['pkwl_action'];
    $username   = $_POST['pkwl_username'];
    $solution   = $_POST['pkwl_solution'];

    // check for valid action
    if($action != "auth") exit("ERROR-INVALID-ACTION");

    // query username and public-key
    $sql = $wpdb->prepare(
      "SELECT `$table_usermeta`.`meta_value`
      FROM `$table_users`, `$table_usermeta`
      WHERE `user_login` = '%s'
      AND `$table_users`.`ID` = `$table_usermeta`.`user_id`
      AND `meta_key` = 'pkwl_public_key'
      LIMIT 0,1",
      $username
    );
    $row = $wpdb->get_row( $sql );

    // save key
    $public_key = $row->meta_value;

    // check if the user has uploaded a key
    if($public_key == NULL || $public_key == "") exit("ERROR-NO-PUBLICKEY");

    // query tlp
    $sql = $wpdb->prepare("SELECT `solution`, `timestamp` FROM `$table_tlp` WHERE `username` = '%s' LIMIT 0,1;", $username);
    $row = $wpdb->get_row( $sql );

    // check if we have a valid tlp
    if($row == NULL || $row->solution != $solution) exit("ERROR-TLP-INVALID");

    // check if tlp is not expired
    $time = time();
    if($time - $row->timestamp > 60) exit("ERROR-TLP-EXPIRED");


    /**
    * Cookie
    */
    global $wpdb;
    $user       = get_userdatabylogin( $username );
    $cookiedata = pkwl_wp_set_auth_cookie( $user->ID, true );
    $cookiedata = substr( $cookiedata, 0, strlen( $cookiedata ) - 1 );

    // add leading 0x to string if it's missing
    $public_key = hexFix($public_key);

    /**
    * get blocksize for rsa encryption:
    *   length of public key in hex form
    *   without leading 0x divided by 2
    *   equals the max. size of a  string
    *   to encrypt at once
    */
    $blocksize = (strlen($public_key) - 2) / 2;

    // split cookiedata in small blocks for the rsa encryption
    $cookiedata = str_split($cookiedata, $blocksize);

    /**
    * RSA Object
    */
    $rsa = new RSA();
    $rsa->setN($public_key);
    $rsa->setE("0x10001");

    // encrypt cookiedata and concat ciphertext
    $output = "";
    for($i = 0; $i < count($cookiedata); $i++){
      $rsa->setPlaintext($cookiedata[$i]);
      $rsa->encrypt();

      $output .= $rsa->getCiphertext();
      $output .= ";";
    }

    // remove trailing semicolon
    $output = substr($output, 0, strlen($output) - 1);

    // remove expired time lock puzzles
    $sql = $wpdb->prepare("DELETE FROM `$table_tlp` WHERE `timestamp` < '%s';", $time - 60);
    $wpdb->query($sql);

    // print ciphertext to client
    echo $output;

    // and we're done.
    exit;
  }
}


/**
* Add custom input field to user options page
*/
function pkwl_show_options( $user ){

  // get users meta keys
  $meta_public_key        = get_user_meta( $user->ID, 'pkwl_public_key' );
  $meta_disable_password  = get_user_meta( $user->ID, 'pkwl_disable_password' );

  // if meta data does not exist, create it
  if( !isset($meta_public_key[0]) ){
    $meta_public_key[0] = "";
  }

  // check the input box
  if( isset($meta_disable_password[0]) && $meta_disable_password[0] == 1 ){
    $meta_disable_password[0] = ' checked=""';
  } else {
    $meta_disable_password[0] = '';
  }

  // print options
  echo '<h3>Public-Key-Web-Login (PKWL)</h3>'
  .'<table class="form-table">'
  .'<tr>'
    .'<th><label for="pkwl_public_key">Public-Key</label></th>'
    .'<td>'
      .'<input id="pkwl_public_key" type="text" name="pkwl_public_key" value="'.$meta_public_key[0].'"/> <span class="description"> Paste your public key here. </span>'
    .'</td>'
  .'</tr>'

  .'<tr>'
    .'<th><label for="pkwl_disable_password">Disable Password-Login?</label></th>'
    .'<td>'
      .'<input id="pkwl_disable_password" type="checkbox" name="pkwl_disable_password" value="1"'.$meta_disable_password[0].'/> <span class="description"> This option removes your password from the database. You will only be able to log in with PKWL from then on. If you disable this option afterwards, you will have to set a new password.</span>'
    .'</td>'
  .'</tr>'

  .'</table>';
}


/**
* Saves public key from user profile input field to db
*/
function pkwl_update_options( $user_id ){

  if( current_user_can( 'edit_user', $user_id ) ){

    // get data via post
    $public_key       = $_POST["pkwl_public_key"];
    $disable_password = $_POST["pkwl_disable_password"];

    // add leading 0x to string if it's missing
    $public_key = hexFix($public_key);

    /**
    * if a public key is set and if the user wants to disable password-login,
    * then overwrite his password hash in the db
    * the user will be logged out
    */
    if($disable_password == NULL || !isset($public_key) || $public_key == ""){

      $disable_password = 0;

    } else {

      $disable_password = 1;

      /**
      * set the password to a value that is not possible by the hash
      * function (= that is not in the set of plaintext values) to
      * disable the login via password
      */
      global $wpdb;
      $wpdb->update($wpdb->users, array('user_pass' => 'PKWL', 'user_activation_key' => ''), array('ID' => $user_id) );

      // apply the change by deleting the cache
      wp_cache_delete($user_id, 'users');
    }

    // input is escaped by wordpress
    update_user_meta( $user_id, 'pkwl_public_key', $public_key);
    update_user_meta( $user_id, 'pkwl_disable_password', $disable_password);

  }
}

?>
