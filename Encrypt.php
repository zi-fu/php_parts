<?php

// 暗号化処理の実装
// 参考：codeigniter4
// https://codeigniter4.github.io/userguide/libraries/encryption.html

class Encrypt
{
    // $key　は変更してください。
    private $key = 'test';
    private $driver = 'OpenSSL';
    private $digest = 'SHA512';
    private $cipher = 'AES-256-CTR';
    private $hmacKey;

    public function __construct(Encryption $config = null)
    {
    }
    
        /**
     * Byte-safe substr()
     *
     * @param string  $str
     * @param integer $start
     * @param integer $length
     *
     * @return string
     */
    protected static function substr($str, $start, $length = null)
    {
        return mb_substr($str, $start, $length, '8bit');
    }

    /**
     * Encode
     *
     * @access    public
     * @param     string    the string to encode
     * @return    string
     */
    public function encode($string, $key = '')
    {
        $enc = $this->encrypt($string);
        return $enc;
    }
    
    /**
     * Decode
     *
     * Reverses the above process
     *
     * @access    public
     * @param     string
     * @return    string
     */
    public function decode($string, $key = '')
    {
        $dec = $this->decrypt($string);
        return $dec;
    }
    
    /**
     * Encrypt - convert plaintext into ciphertext
     *
     * @param string            $data   Input data
     * @param array|string|null $params Overridden parameters, specifically the key
     *
     * @throws ErrorException
     *
     * @return string
     */
    public function encrypt($data, $params = null)
    {
        try{
            if (empty($this->key))
            {
                throw new \ErrorException('keyが存在しません。');
            }
            // derive a secret key
            $secret = \hash_hkdf($this->digest, $this->key);
            
            // 確認用
            echo 'digest :: ';var_dump($this->digest);
            echo '<br>key :: ';var_dump($this->key);
            echo '<br>cipher :: ';var_dump($this->cipher);
            
            // basic encryption
            $iv = ($ivSize = \openssl_cipher_iv_length($this->cipher)) ? \openssl_random_pseudo_bytes($ivSize) : null;

            // 確認用
            echo '<br>iv :: ';var_dump($iv);

            if ($ivSize === false) {
                throw new \ErrorException('サポートしていない暗号化方式です。');
            }

            $data = \openssl_encrypt($data, $this->cipher, $secret, OPENSSL_RAW_DATA, $iv);

            if ($data === false)
            {
                throw new \ErrorException('暗号化に失敗しました。');
            }

            $result = $iv . $data;
            $hmacKey = \hash_hmac($this->digest, $result, $secret, true);

            // return $hmacKey . $result;
            $encrypted = $hmacKey . $result;
            return base64_encode($encrypted);

        } catch(\Throwable $e) {
            throw new \ErrorException($e);
        }
    }

    /**
     * Decrypt - convert ciphertext into plaintext
     *
     * @param string            $data   Encrypted data
     * @param array|string|null $params Overridden parameters, specifically the key
     *
     * @throws ErrorException
     *
     * @return string
     */
    public function decrypt($data, $params = null)
    {
        try{
            if (empty($this->key))
            {
                throw new \ErrorException('keyが存在しません。');
            }

            $data = base64_decode($data);
            
            // 確認用
            echo '<br>digest :: ';var_dump($this->digest);
            echo '<br>key :: ';var_dump($this->key);
            echo '<br>cipher :: ';var_dump($this->cipher);

            // derive a secret key
            $secret = \hash_hkdf($this->digest, $this->key);

            $hmacLength = self::substr($this->digest, 3) / 8;
            $hmacKey    = self::substr($data, 0, $hmacLength);
            $data       = self::substr($data, $hmacLength);
            $hmacCalc   = \hash_hmac($this->digest, $data, $secret, true);
            if (! hash_equals($hmacKey, $hmacCalc))
            {
                throw new \ErrorException('複合化に失敗しました。');
            }
            
            if ($ivSize = \openssl_cipher_iv_length($this->cipher))
            {
                $iv   = self::substr($data, 0, $ivSize);
                $data = self::substr($data, $ivSize);
            }
            else
            {
                $iv = null;
            }
            
            // 確認用
            echo '<br>iv :: ';var_dump($iv);

            return \openssl_decrypt($data, $this->cipher, $secret, OPENSSL_RAW_DATA, $iv);
            
        } catch(\Throwable $e) {
            throw new \ErrorException($e);
        }
    }
}


$Encrypt = new Encrypt;
echo '<br>暗号化検証　　　　「hello 沖縄」<br><br>';

$text = "hello 沖縄";
$encode = $Encrypt->encode($text);
echo '<br>encode :: ';var_dump($encode);

echo '<br><br><br>';

$decode = $Encrypt->decode($encode);
echo '<br>decode :: ';var_dump($decode);

