<?php
namespace Src;

include_once 'aliyun-php-sdk-core/Config.php';
use Sts\Request\V20150401 as Sts;

class StsLog {
    public function genStsToken (string $accessKeyID, string $accessKeySecret, string $roleArn, string $policy, string $tokenExpire = "900") {
        $iClientProfile = \DefaultProfile::getProfile("cn-hangzhou", $accessKeyID, $accessKeySecret);
        $client = new \DefaultAcsClient($iClientProfile);

        $request = new Sts\AssumeRoleRequest();
        $request->setRoleSessionName("client_name");
        $request->setRoleArn($roleArn);
        $request->setPolicy($policy);
        $request->setDurationSeconds($tokenExpire);
        $response = $client->doAction($request);

        $rows = array();
        $body = $response->getBody();
        $content = json_decode($body);
        if ($response->getStatus() == 200)
        {
            $rows['StatusCode'] = 200;
            $rows['AccessKeyId'] = $content->Credentials->AccessKeyId;
            $rows['AccessKeySecret'] = $content->Credentials->AccessKeySecret;
            $rows['Expiration'] = $content->Credentials->Expiration;
            $rows['SecurityToken'] = $content->Credentials->SecurityToken;
        }
        else
        {
            $rows['StatusCode'] = 500;
            $rows['ErrorCode'] = $content->Code;
            $rows['ErrorMessage'] = $content->Message;
        }
        return $rows;
    }
}