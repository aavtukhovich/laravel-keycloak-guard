<?php

namespace KeycloakGuard;

use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use KeycloakGuard\Exceptions\InvalidWellKnownException;
use KeycloakGuard\Exceptions\TokenException;

class KeycloakGuard implements Guard
{
	private $config;
	private $user;
	private $provider;
	private $decodedToken;
	private $public_key;
	private $token;
	private $wellKnown;

	public function __construct(UserProvider $provider, Request $request)
	{
		$this->config = config('keycloak');
		$this->user = null;
		$this->provider = $provider;
		$this->decodedToken = null;
		$this->token = null;
		$this->wellKnown = null;
		$this->request = $request;
		if (Cache::has('wellKnown') && Cache::has('keycloak_public_key')) {
			$this->wellKnown = json_decode(Cache::get('wellKnown'));
			$this->public_key = json_decode(Cache::get('keycloak_public_key'));
		} else {
			$this->loadwellKnown();
		}
		$this->authenticate();
	}

	public function loadWellKnown()
	{
		try {
			$response =  Http::get($this->config['well-known']);
			$this->wellKnown = $response->object();
			$this->public_key = Http::get($this->wellKnown->issuer)->object()->public_key;
			Cache::put('wellKnown', json_encode($this->wellKnown));
			Cache::put('keycloak_public_key', json_encode($this->public_key));
		} catch (\Exception $e) {
			throw new InvalidWellKnownException($e->getMessage());
		}
	}

	/**
	 * Decode token, validate and authenticate user
	 *
	 * @return mixed
	 */

	private function authenticate()
	{
		try {
			$this->token = $this->request->bearerToken();
			if ($this->config['introspect']) {
				$introspect =  Http::asForm()->post($this->wellKnown->introspection_endpoint, array(
					'token' => $this->token,
					'client_id' => $this->config['client_resource'],
				        'client_secret' => $this->config['client_secret'],
				))->object();
				if (isset($introspect->error)) {
					return false;
				} elseif ($introspect->active) {
					$this->decodedToken = Token::decode($this->token, $this->public_key);
				} else {
					return false;
				}
			} else {
				if (!is_null($this->token))
					$this->decodedToken = Token::decode($this->token, $this->public_key);
			}
		} catch (\Exception $e) {
			throw new TokenException($e->getMessage());
		}

		if ($this->decodedToken) {
			$this->validate();
		}
	}


	/**
	 * Determine if the current user is authenticated.
	 *
	 * @return bool
	 */
	public function check()
	{
		return !is_null($this->user());
	}

	/**
	 * Determine if the guard has a user instance.
	 *
	 * @return bool
	 */
	public function hasUser()
	{
		return !is_null($this->user());
	}

	/**
	 * Determine if the current user is a guest.
	 *
	 * @return bool
	 */
	public function guest()
	{
		return !$this->check();
	}

	/**
	 * Get the currently authenticated user.
	 *
	 * @return \Illuminate\Contracts\Auth\Authenticatable|null
	 */
	public function user()
	{
		if (is_null($this->user)) {
			return null;
		}

		$this->user->token = $this->decodedToken;

		return $this->user;
	}

	/**
	 * Get the ID for the currently authenticated user.
	 *
	 * @return int|null
	 */
	public function id()
	{
		if ($user = $this->user()) {
			return $this->user()->id;
		}
	}

	/**
	 * Validate a user's credentials.
	 *
	 * @param  array  $credentials
	 * @return bool
	 */
	public function validate(array $credentials = [])
	{
		if (!$this->decodedToken) {
			return false;
		}
		$class = $this->provider->getModel();
		$user = new $class();
		$this->setUser($user);
		return true;
	}

	/**
	 * Set the current user.
	 *
	 * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
	 * @return void
	 */
	public function setUser(Authenticatable $user)
	{
		$this->user = $user;
	}

	/**
	 * Returns full decoded JWT token from athenticated user
	 *
	 * @return mixed|null
	 */
	public function token()
	{
		return json_encode($this->decodedToken);
	}

	/**
	 * Check if authenticated user has a especific role into resource
	 * @param string $resource
	 * @param string $role
	 * @return bool
	 */
	public function hasRole($role)
	{
		$token_resource_access = $this->decodedToken->resource_access;
		if (array_key_exists($this->config['client_resource'], $token_resource_access)) {
			$token_resource_values = (array) $token_resource_access[$this->config['client_resource']];

			if (
				array_key_exists('roles', $token_resource_values) &&
				in_array($role, $token_resource_values['roles'])
			) {
				return true;
			}
		}
		return false;
	}
}
