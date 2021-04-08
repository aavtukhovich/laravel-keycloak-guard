<?php

return [
	'well-known' => env('KEYCLOAK_WELL_KNOWN', null),
	'client_resource' => env('KEYCLOAK_CLIENT_RESOURCE', null),
	'client_secret' => env('KEYCLOAK_CLIENT_SECRET', null),
	'introspect' => env('KEYCLOAK_INTROSPECT', true)
];
