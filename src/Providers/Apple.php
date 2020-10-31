<?php

namespace Overtrue\Socialite\Providers;

use CoderCat\JWKToPEM\JWKConverter;
use Firebase\JWT\JWT;
use GuzzleHttp\Psr7\Stream;
use Overtrue\Socialite\Exceptions\BadConfigException;
use Overtrue\Socialite\Exceptions\Exception;
use Overtrue\Socialite\User;

class Apple extends Base
{
    public const NAME = 'apple';
    protected string $baseUrl        = 'https://appleid.apple.com/auth';
    protected array  $scopes         = ['name', 'email'];
    protected string $scopeSeparator = ' ';
    protected array  $responseTypes  = ['code', 'id_token'];
    protected int $encodingType = PHP_QUERY_RFC3986;

    /**
     * Apple constructor.
     *
     * @param array $config
     *
     * @throws BadConfigException
     */
    public function __construct(array $config)
    {
        parent::__construct($config);

        if (!$this->config->has('client_secret')) {
            if ($this->config->has('private_key') &&
                $this->config->has('team_id') &&
                $this->config->has('key_id')) {

                $time = time();
                $payload = [
                    'iss' => $this->config->get('team_id'),
                    'aud' => 'https://appleid.apple.com',
                    'sub' => $this->getClientId(),
                    'iat' => $time,
                    'exp' => $time + 15777000
                ];

                $privateKey = $this->config->get('private_key');

                $jwt = JWT::encode($payload, $privateKey, 'ES256');

                $this->config->set('client_secret', $jwt);
            } else {
                throw new BadConfigException('Incomplete configuration.');
            }
        }
    }

    protected function getAuthUrl(): string
    {
        return $this->buildAuthUrlFromBase($this->baseUrl . '/authorize');
    }

    protected function getTokenUrl(): string
    {
        return $this->baseUrl . '/token';
    }

    /**
     * @param string $token
     *
     * @return array
     */
    protected function getUserByToken(string $token): array
    {
        throw new \InvalidArgumentException('Unable to use \'token\' get User info.');
    }

    public function userFromCode(string $code): User
    {
        throw new \InvalidArgumentException('Unable to use \'Code\' get User info.');
    }

    protected function mapUserToObject(array $user): User
    {
        return new User(
            [
                'name'  => $user['name'] ? $user['name']['firstName'] . $user['name']['lastName'] : null,
                'email' => $user['email'] ?? null,
                'id'    => $user['id_token'] ?? null
            ]
        );
    }

    protected function getCodeFields(): array
    {
        $fields = array_merge(
            [
                'client_id'     => $this->getClientId(),
                'redirect_uri'  => $this->redirectUrl,
                'response_type' => implode(' ', $this->responseTypes),
                'scope'         => $this->formatScopes($this->scopes, $this->scopeSeparator),
                'response_mode' => 'form_post'
            ],
            $this->parameters
        );

        if ($this->state) {
            $fields['state'] = $this->state;
        }

        return $fields;
    }

    public function tokenFromCode(string $code): array
    {
        $response = $this->getHttpClient()->post(
            $this->getTokenUrl(),
            [
                'form_params' => $this->getTokenFields($code),
                'headers'     => [
                    'Content-Type' => 'application/x-www-form-urlencoded'
                ],
            ]
        );

        return $this->normalizeAccessTokenResponse($response->getBody()->getContents());
    }

    protected function getTokenFields(string $code): array
    {
        return [
            'client_id'     => $this->getClientId(),
            'client_secret' => $this->getClientSecret(),
            'code'          => $code,
            'grant_type'    => 'authorization_code',
            'redirect_uri'  => $this->redirectUrl,
        ];
    }

    /**
     * parse id_token to obtain unique user id
     *
     * @param string $idToken
     *
     * @return string
     * @throws Exception
     * @throws \CoderCat\JWKToPEM\Exception\Base64DecodeException
     * @throws \CoderCat\JWKToPEM\Exception\JWKConverterException
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function parseIdToken(string $idToken): string
    {

        $response = $this->getHttpClient()->get($this->baseUrl . '/keys');
        if ($response instanceof Stream) {
            $response->rewind();
            $response = $response->getContents();
        }

        if (\is_string($response)) {
            $response = json_decode($response, true) ?? [];
        }

        if (!isset($response['keys'])) {
            throw new Exception('The Response is not expected.');
        }

        foreach ($response['keys'] as $jwk) {
            $publicKey = (new JWKConverter())->toPEM($jwk);
            $decoded = JWT::decode($idToken, $publicKey, array('RS256'));
            if (isset($decoded['sub'])) {
                return $decoded['sub'];
            }
        }


        throw new Exception('Cannot handle ID_token');
    }

}