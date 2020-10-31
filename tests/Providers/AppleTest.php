<?php

use PHPUnit\Framework\TestCase;
use Overtrue\Socialite\Providers\Apple;

class AppleTest extends TestCase {
    public function testConstructSetClientSecret()
    {
        $app = new Apple([
            'client_id'    => 'client_id',
            'key_id' => 'key_id',
            'team_id' => 'team_id',
            'redirect_url' => 'http://localhost/socialite/callbak.php',
            'private_key'   => '-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGbfn650AsU4fvDU1ESIffXvidT7nQOkp8K9xax9tJPVoAoGCCqBHM9V
AYItoUQDQgAEU3xhC8lDxwhK/ElIZv0EDZrdjqW+ufNOG+Eaumbjb5WkzDrlb0Jq
c9v9HkKXM1yegcaOMpTZk3vUEMsTo5c3pA==
-----END EC PRIVATE KEY-----'
        ]);

        $this->assertSame(true, $app->getConfig()->has('client_secret'));
    }

    public function testAppleDriverCanGetRedirectPath()
    {
        $app = new Apple([
            'client_id'    => 'client_id',
            'key_id' => 'key_id',
            'team_id' => 'team_id',
            'redirect_url' => 'http://localhost/socialite/callbak.php',
            'private_key'   => '-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGbfn650AsU4fvDU1ESIffXvidT7nQOkp8K9xax9tJPVoAoGCCqBHM9V
AYItoUQDQgAEU3xhC8lDxwhK/ElIZv0EDZrdjqW+ufNOG+Eaumbjb5WkzDrlb0Jq
c9v9HkKXM1yegcaOMpTZk3vUEMsTo5c3pA==
-----END EC PRIVATE KEY-----'
        ]);

        $this->assertSame(
            'https://appleid.apple.com/auth/authorize?client_id=client_id&redirect_uri=' . urlencode('http://localhost/socialite/callbak.php') .'&response_type=code%20id_token&scope=name%20email&response_mode=form_post',
            $app->redirect());
    }
}