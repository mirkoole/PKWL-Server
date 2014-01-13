<?php
/**
* RSA.class.php
* by Mirko Oleszuk
*/


// public math functions:

// bit-shift-left with gmp
function gmp_bit_shift_left($x, $bits){
  return gmp_mul($x, gmp_pow("2", $bits));
}

// bit-shift-right with gmp
function gmp_bit_shift_right($x, $bits){
  return gmp_div($x, gmp_pow("2", $bits));
}

/**
* hexFix(): adds a leading "0x" to the input string if it's missing
* @param string $hex string to be fixed
* @return string with leading "0x"
*/
function hexFix($hex){
  if(0 != substr_compare($hex, "0x", 0, 2, TRUE)){
    $hex = "0x" . $hex;
  }
  return $hex;
}


/**
 * The RSA Class
 *
 * This class provides some RSA functionality.
 *
 * @author Mirko Oleszuk <mirko@oleszuk.de>
 * @copyright 2013 Mirko Oleszuk
 * @license The MIT License (MIT)
 * @version 0.1
*/
class RSA {

  /**
  * A private Variable
  *
  * @var string stores the RSA-Module number of the RSA key as hex number
  */
  private $n = NULL;

  /**
  * A private variable
  *
  * @var string stores the decryption expontent of the rsa key as hex number
  */
  private $d = NULL;

  /**
  * A private variable
  *
  * @var string stores the encryption expontent of the rsa key as hex number
  */
  private $e = NULL;

  /**
  * A private variable
  *
  * @var string stores the plaintext
  */
  private $plaintext = NULL;

  /**
  * A private variable
  *
  * @var string stores the ciphertext
  */
  private $ciphertext = NULL;


  /**
  * Getter
  */
  public function getPlaintext(){
    return $this->plaintext;
  }
  public function getCiphertext(){
    return $this->ciphertext;
  }


  /**
  * Setter
  */
  public function setPlaintext($p){
    $this->plaintext = $p;
  }
  public function setCiphertext($c){
    $this->ciphertext = $c;
  }
  public function setN($n){
    $this->n = hexFix($n);
  }
  public function setE($e){
    $this->e = hexFix($e);
  }
  public function setD($d){
    $this->d = hexFix($d);
  }

  /**
  * encrypt(): encrypts string with $this key
  * Note: this can only encrypt strings shorter than key size in byte
  * @param string $plaintext to encrypt
  * @return string contains the encrypted ciphertext
  */
  public function encrypt(){

    // convert hex-string (base 16) to gmp big integer
    $n = gmp_init($this->n, 16);
    $e = gmp_init($this->e, 16);

    // convert given string to hex and add leading 0x
    $m = "0x" . bin2hex( $this->plaintext );

    // convert hex-string (base 16) to gmp big integer
    $m = gmp_init($m);

    // encrypt: c = m^e % n
    $this->ciphertext = gmp_strval(gmp_powm($m, $e, $n), 16);
  }

  /**
  * decrypt(): decrypt ciphertext with $this key
  * @param string $ciphertext contains encrypted string
  * @return string contains decrypted plaintext of given ciphertext
  */
  public function decrypt()
  {
    // convert hex-string (base 16) to gmp big integer
    $n = gmp_init($this->n, 16);
    $d = gmp_init($this->d, 16);
    $s = gmp_init($this->ciphertext, 16);

    // decrypt with rsa formula: m = c^d mod n
    $m = gmp_powm($s, $d, $n);

    // convert gmp big int to string
    $m = gmp_strval($m);


    $result = "";
    while($m > 0)
    {
      // $m & 255
      $result = chr(gmp_strval(gmp_and($m, "255"))) . $result;

      // $m >> 8
      $m = gmp_strval(gmp_bit_shift_right($m, "8"));
    }
    $this->plaintext = $result;
  }
}

?>
