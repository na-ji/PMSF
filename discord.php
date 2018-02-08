<?php

require __DIR__ . '/vendor/autoload.php';

function initDiscordAuth()
{
    global $discordClientId, $discordClientSecret, $discordRedirectUrl, $discordServerId;
	$provider = new \Discord\OAuth\Discord(
		[
			'clientId' => $discordClientId,
			'clientSecret' => $discordClientSecret,
			'redirectUri' => $discordRedirectUrl,
		]
	);

    // When Discord redirects the user back here, there will be a "code" and "state" parameter in the query string
	if (isset($_GET['code']) && $_GET['code']) {
		// Verify the state matches our stored state
		if (!$_GET['state'] || $_SESSION['state'] !== $_GET['state']) {
			http_response_code(403);
			die('Hop là');
		}

		// Exchange the auth code for a token
		$token = $provider->getAccessToken(
			'authorization_code',
			[
				'code' => $_GET['code'],
			]
		);

		// Get the user object.
		$user = $provider->getResourceOwner($token);

		// Get the guilds and connections.
		$guildsCollection = $user->guilds;
		$isGrantedAccess = false;
		$isGrantedFullAccess = false;
		foreach ($guildsCollection as $guild) {
			if ($guild->id === $discordServerId) {
				$isGrantedAccess = true;
				$isGrantedFullAccess = $guild->owner;
			}
		}

		if (!$isGrantedAccess) {
			http_response_code(403);
			die('Hop là');
		}

		$_SESSION['has_full_access'] = $isGrantedFullAccess;
		$_SESSION['access_token'] = json_encode($token->jsonSerialize());
		header('Location: '.$discordRedirectUrl);
	}

	if ($_SESSION['access_token']) {
		// Get the user object.
		$token = json_decode($_SESSION['access_token'], $assoc = true);
		$accessToken = new \League\OAuth2\Client\Token\AccessToken($token);
		$user = $provider->getResourceOwner($accessToken);
	} else {
		// Start the login process by sending the user to Discord's authorization page
		// Generate a random hash and store in the session for security
		$_SESSION['state'] = hash('sha256', microtime(true).rand().$_SERVER['REMOTE_ADDR']);
		unset($_SESSION['access_token']);
		header(
			'Location:'.$provider->getAuthorizationUrl(
				[
					'scope' => [
						'identify',
						'email',
						'guilds',
					],
					'state' => $_SESSION['state']
				]
			)
		);
		exit();
	}
}

if ($enableDiscordAuth) {
	initDiscordAuth();
}
