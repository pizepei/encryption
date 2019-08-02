<?php
namespace pizepei\encryption;
use pizepei\helper\Helper;

/**
 * SHA1 class
 *
 * 计算公众平台的消息签名接口.
 */
class SHA1
{
    /**
     * 用SHA1算法生成安全签名
     * @param string $token 票据
     * @param string $timestamp 时间戳
     * @param string $nonce 随机字符串
     * @param string $encrypt_msg 密文消息
     * @return null|string
     */
	public function getSHA1($token, $timestamp, $nonce, $encrypt_msg)
	{
		//排序
		try {
			$array = array($encrypt_msg, $token, $timestamp, $nonce);
			sort($array, SORT_STRING);
			$str = implode($array);
			return sha1($str);
		} catch (\Exception $e) {
            return null;
		}
	}
    /**
     * 用SHA1算法生成安全签名
     * @param string $token 票据
     * @param string $encrypt_msg 密文消息
     * @return null|string
     */
	public function setSignature($token,$encrypt_msg)
    {
        $nonce = Helper::str()->int_rand(10);
        $timestamp = time();
        $signature = $this->getSHA1($token,$timestamp,$nonce,$encrypt_msg);
        if (!$signature) return null;
        return[
            'nonce'=>$nonce,
            'timestamp'=>$timestamp,
            'signature'=>$signature,
            'encrypt_msg'=>$encrypt_msg,
        ];
    }
    /**
     * 验证签名是否正确
     * @param string $token 票据
     * @param string $encrypt_msg 密文消息
     * @return null|string
     */
    public function verifySignature($token,$data)
    {
        $Signature = $this->getSHA1($token,$data['timestamp'],$data['nonce'],$data['encrypt_msg']);
        if ($Signature ===$data['signature']){
            return true;
        }
        return false;
    }

}


?>