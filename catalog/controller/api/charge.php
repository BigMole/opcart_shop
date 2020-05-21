<?php


class ControllerApiCharge  extends Controller
{

    private $config=array(
        'agencyId'=>'549440189990001',   //测试用商户资料
        'childMerchantId'=>'',   //测试用商户资料
        'terminalId' => '20003962' , //测试用商户资料
        'url'=>'https://testpay.sicpay.com/backSecure.do',//测试用地址
    );




    public function index(){

        $post = $this->request->post;


    }





}



/**
 * 一户一码
 */
class PaySign{

    public function sendEncodeData($json, $config){
        $json_content = json_encode($json);

        //随机生成aes密钥
        $aes_key = $this->randomKeys(16);
        //商户RSA私钥
        $private_rsa_key_path = $this->getPath() . $config['agencyId'] . '/' . $config['agencyId'].  '.pem';


        // var_dump($private_rsa_key_path);
        $private_rsa_key = file_get_contents($private_rsa_key_path);
        //我司平台RSA公钥
        $public_rsa_key_path =  $this->getPath() . $config['agencyId'] . '/' . 'GHT_ROOT.pem';


        //  var_dump($public_rsa_key_path);
        $public_rsa_key = file_get_contents($public_rsa_key_path);

        //用上面随机生成的aes密钥加密请求报文
        $data['encryptData'] = $this->aesEncode($json_content, $aes_key);
        //用我司平台rsa公钥加密上面随机生成的aes密钥
        $data['encryptKey'] = $this->rsaEncode($aes_key, $public_rsa_key);
        //用商户ras私钥签名
        $data['signData'] = $this->rsaSign($json_content, $private_rsa_key);
        $data['agencyId'] = $config['agencyId'];
        $data_content = json_encode($data);

        //发送请求
        $request_result = $this->httpPost($data_content, $config['url']);

        //解密返回报文
        $result_json = json_decode($request_result,true);

        //用商户私钥解密aes密钥（是由平台随机生成的）
        $result_aes_key = $this->rsaDecode($result_json['encryptKey'], $private_rsa_key);
        //用aes密钥解密报文
        $decode_content = $this->aesDecode($result_json['encryptData'],$result_aes_key);
        //用平台公钥验签
        if($this->verifySign($decode_content, $result_json['signData'], $public_rsa_key)){
            return $decode_content;
        } else {
            //验签失败
            return false;
        }
    }
    public function sendEncodeData01($result_json, $config){

        $private_rsa_key_path = $this->getPath() . $config['agencyId'] . '/' . $config['agencyId'].  '.pem';

        // var_dump($private_rsa_key_path);
        $private_rsa_key = file_get_contents($private_rsa_key_path);
        //我司平台RSA公钥
        $public_rsa_key_path =  $this->getPath() . $config['agencyId'] . '/' . 'GHT_ROOT.pem';

        $public_rsa_key = file_get_contents($public_rsa_key_path);

        //用商户私钥解密aes密钥（是由平台随机生成的）

        $result_aes_key = $this->rsaDecode($result_json['encryptKey'], $private_rsa_key);

        //用aes密钥解密报文
        $decode_content = $this->aesDecode($result_json['encryptData'],$result_aes_key);
        //用平台公钥验签
        if($this->verifySign($decode_content, $result_json['signData'], $public_rsa_key)){
            return $decode_content;
        } else {
            //验签失败
            return false;
        }
    }

    private function aesEncode($data, $aes_key){
        $encrypt_data = openssl_encrypt($this->pad($data), "aes-128-ecb", $aes_key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING);
        return base64_encode($encrypt_data);
    }

    public function aesDecode($data,$aes_key){
        $data = base64_decode($data);
        return openssl_decrypt($data, "aes-128-ecb", $aes_key, OPENSSL_RAW_DATA);
    }

    private function rsaEncode($data, $public_rsa_key){
        $ret = false;
//        if (!self::_checkPadding(OPENSSL_PKCS1_PADDING, 'en')){
//            return 'padding error';
//        }
        $key = openssl_get_publickey($public_rsa_key);
        if (openssl_public_encrypt($data,$result,$key,OPENSSL_PKCS1_PADDING)){
            $ret = base64_encode($result);
        }
        return $ret;
    }

    private function rsaDecode($data, $private_rsa_key){
        $ret = false;
        $data = base64_decode($data);

        if ($data !== false){
            if (openssl_private_decrypt($data, $result, $private_rsa_key, OPENSSL_PKCS1_PADDING)){

                $ret = $result;
            }
        }
        return $ret;
    }

    private function rsaSign($data, $private_rsa_key) {
        $res = openssl_get_privatekey ($private_rsa_key);
        openssl_sign($data,$sign, $res);
        openssl_free_key($res);
        $sign = base64_encode($sign);
        return $sign;
    }

    private function verifySign($data, $signData, $public_rsa_key){
        $signData =base64_decode($signData);
        $res = openssl_get_publickey($public_rsa_key);
        $result = openssl_verify($data, $signData, $res);
        openssl_free_key($res);
        if($result === 1){
            return true;
        } else {
            return false;
        }
    }

    private function httpPost($data,$url){
        // print_r($data);
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-type: application/json'));
        curl_setopt($ch,CURLOPT_TIMEOUT,600);
        curl_setopt($ch,CURLOPT_URL,$url);
        curl_setopt($ch,CURLOPT_POST,true);
        curl_setopt($ch,CURLOPT_POSTFIELDS,$data);
        curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);
        if (strpos($url, 'https') !== false) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
            curl_setopt($ch, CURLOPT_SSLVERSION, 1);
        }
        $ret_data = trim(curl_exec($ch));
        curl_close($ch);
        return $ret_data;

    }

    //获取当前绝对路径
    private function getPath(){

        return DIR_DOC.'/';

    }

    private function randomKeys($length)
    {
        $key = '';
        $pattern = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLOMNOPQRSTUVWXYZ';
        for($i=0;$i<$length;$i++) {
            $key .= $pattern{mt_rand(0,35)};    //生成php随机数
        }
        return $key;
    }

    private function pad($data, $blocksize = 16) {
        $pad = $blocksize - (strlen($data) % $blocksize);
        return $data . str_repeat(chr($pad), $pad);
    }

}
