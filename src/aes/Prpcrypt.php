<?php
/**
 * Created by PhpStorm.
 * User: pizepei
 * Date: 2018/6/27
 * Time: 11:23
 * @title aes 加解密
 */
namespace pizepei\encryption\aes;

class Prpcrypt
{

    public $key;
    /**
     * Prpcrypt constructor.
     * @param $key
     */
    function __construct($key)
    {
        $this->key = base64_decode("{$key}=");
    }

    /**
     * @Author pizepei
     * @Created 2019/4/6 15:47
     *
     * @param string $text 需要加密的明文
     * @param string $appid APPID
     * @param bool $urlencode
     * @return null|string
     * @title  对明文进行加密
     * @explain 一般是方法功能说明、逻辑说明、注意事项等。
     */
    public function encrypt($text, $appid,$urlencode=true)
    {
        try {
            $random = $this->getRandomStr();
            $iv = substr($this->key, 0, 16);
            $pkcEncoder = new PKCS7Encoder();
            $text = $pkcEncoder->encode($random . pack("N", strlen($text)) . $text . $appid);
            $encrypted = openssl_encrypt($text, 'AES-256-CBC', substr($this->key, 0, 32), OPENSSL_ZERO_PADDING, $iv);
            if($urlencode){
                $encrypted = urlencode($encrypted);
            }
            return $encrypted;
        } catch (\Exception $e) {
            return null;
        }
    }


    /**
     * @Author pizepei
     * @Created 2019/4/6 15:49
     * @param string $encrypted 需要解密的密文
     * @param bool $urldecode
     * @return array|null
     * @title  对密文进行解密
     * @explain 一般是方法功能说明、逻辑说明、注意事项等。
     */
    public function decrypt($encrypted,$urldecode=true)
    {
        if($urldecode){
            $encrypted = urldecode($encrypted);
        }
        try {
            $iv = substr($this->key, 0, 16);
            $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', substr($this->key, 0, 32), OPENSSL_ZERO_PADDING, $iv);
        } catch (\Exception $e) {
            return null;
        }
        try {
            $pkcEncoder = new PKCS7Encoder();
            $result = $pkcEncoder->decode($decrypted);
            if (strlen($result) < 16) {
                return  null;
            }
            $content = substr($result, 16, strlen($result));
            $len_list = unpack("N", substr($content, 0, 4));
            $xml_len = $len_list[1];
            return [0, substr($content, 4, $xml_len), substr($content, $xml_len + 4)];
        } catch (\Exception $e) {
            return null;
        }
    }
    /**
     * 随机生成16位字符串
     * @param string $str
     * @return string 生成的字符串
     */
    function getRandomStr($str = "")
    {
        $str_pol = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
        $max = strlen($str_pol) - 1;
        for ($i = 0; $i < 16; $i++) {
            $str .= $str_pol[mt_rand(0, $max)];
        }
        return $str;
    }

}
