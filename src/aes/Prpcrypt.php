<?php
/**
 * Created by PhpStorm.
 * User: pizepei
 * Date: 2018/6/27
 * Time: 11:23
 * @title aes 加解密
 */
namespace pizepei\encryption\aes;

use pizepei\encryption\SHA1;

class Prpcrypt
{
    public $SHA1;

    public $key;
    /**
     * Prpcrypt constructor.
     * @param $key
     */
    function __construct($key)
    {
        $this->SHA1 = new SHA1();
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
     * 生产一个加密数据
     * @param $text
     * @param $appid
     * @param $token
     * @param bool $urlencode
     * @return array
     * @throws \Exception
     */
    public function yieldCiphertext(string  $text, string $appid, string  $token,bool $urlencode=true):array
    {
        # 获取密文
        $Ciphertext = $this->encrypt($text,$appid,$urlencode);
        if ($Ciphertext ==NULL){throw new \Exception('Encryption failed ');}
        # 设置签名
        $data = $this->SHA1->setSignature($token,$Ciphertext);
        if ($data == null){ throw new \Exception('Error setting signature');}
        $data['urlencode'] = $urlencode;
        return $data;
    }

    /**
     * 验证并获取解密信息
     * @param string $token
     * @param array $data [timestamp,nonce,encrypt_msg,urldecode]
     * @return mixed
     * @throws \Exception
     */
    public function decodeCiphertext(string $token,array $data)
    {
        # 验证签名
        $res = $this->SHA1->verifySignature($token,$data);
        if (!$res){throw new \Exception('Signature error');}
        # 解密信息
        $res = $this->decrypt($data['encrypt_msg'],$data['urldecode']);
        if (!$res || !isset($res[1])){ throw new \Exception('decryption failure ');}
        return $res[1];
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
