<?php
/**
 * DokuWiki Plugin authdiscourse (Auth Component)
 */

class auth_plugin_authdiscourse extends auth_plugin_authplain
{

    const TOKEN_COOKIE = 'DWDisc';
    const REQUIRED_USERINFO = ['nonce', 'username', 'email'];

    /**
     * Constructor.
     */
    public function __construct()
    {
        parent::__construct();
        $this->cando['external'] = true;
    }

    /**
     * Enables login with SSO tokens
     *
     * @param string $user
     * @param string $pass
     * @param bool $sticky
     * @return bool
     */
    public function trustExternal($user, $pass, $sticky = false)
    {
        global $INPUT;
        global $conf;

        $sig = $INPUT->str('sig');
        $sso = $INPUT->str('sso');

        // token in query string?
        if ($sig && $sso && $this->validateToken($sig, $sso)) {
            $this->setTokenCookie(''); // cookie no longer needed

            // get user info from response
            $ssoResponse = [];
            parse_str(base64_decode($sso), $ssoResponse);

            if (!$this->validateResponse($ssoResponse)) {
                msg($this->getLang('error_login'), -1);
                return false;
            }

            $userinfo = [
                'user' => $this->cleanUser($ssoResponse['username']),
                'name' => $ssoResponse['name'] ?? $ssoResponse['username'],
                'mail' => $ssoResponse['email'],
                'grps' => !empty($ssoResponse['groups']) ? explode(',', $ssoResponse['groups']) : [],
            ];
            $userinfo['grps'][] = $conf['defaultgroup']; // makes sure users are in default group
            $userinfo['grps'] = array_map([$this, 'cleanGroup'], $userinfo['grps']);

            // does a local user with this email exist?
            $found = $this->retrieveUsers(0, 1, ['mail' => '^' . preg_quote_cb($userinfo['mail']) . '$']);
            if ($found) {
                // update user with SSO data
                $oldusername = key($found);
                if (!$this->modifyUser($oldusername, $userinfo)) {
                    msg($this->getLang('error_login'), -1);
                    return false;
                }
            } else {
                // create new user
                if (!$this->addUser($userinfo)) {
                    msg($this->getLang('error_login'), -1);
                    return false;
                }
            }

            return $this->storeLogin($userinfo['user'], $userinfo);
        }

        // session set? trust it
        if (isset($_SESSION[DOKU_COOKIE]['auth']['user'])) {
            return $this->storeLogin($_SESSION[DOKU_COOKIE]['auth']['user'], $_SESSION[DOKU_COOKIE]['auth']['info']);
        }

        return false;
    }

    /**
     * Saves nonce/token in cookie for comparison with response from SSO provider
     *
     * @param string $token
     */
    public function setTokenCookie($token)
    {
        $time = ($token) ? 0 : time() - 3600 * 24; // empty toke expires the cookie

        global $conf;
        $cookieDir = empty($conf['cookiedir']) ? DOKU_REL : $conf['cookiedir'];
        setcookie(
            \auth_plugin_authdiscourse::TOKEN_COOKIE,
            $token,
            $time,
            $cookieDir,
            '',
            ($conf['securecookie'] && is_ssl()),
            true
        );
    }

    /**
     * Overwrite authplain cleaning
     *
     * @param string $user
     * @return string
     */
    public function cleanUser($user)
    {
        return strtolower($user);
    }

    /**
     * Store login data in session
     *
     * @param string $user
     * @param array $userinfo
     * @return true
     */
    protected function storeLogin($user, $userinfo)
    {
        global $USERINFO;
        global $INPUT;

        $USERINFO = $userinfo;
        $INPUT->server->set('REMOTE_USER', $user);

        $_SESSION[DOKU_COOKIE]['auth']['user'] = $user;
        $_SESSION[DOKU_COOKIE]['auth']['info'] = $userinfo;

        return true;
    }

    /**
     * Creates a new user
     *
     * @param array $userinfo
     * @return bool|int|null
     */
    protected function addUser($userinfo)
    {
        $pwd = auth_pwgen($userinfo['user']);

        return $this->triggerUserMod(
            'create',
            [
                $userinfo['user'],
                $pwd,
                $userinfo['name'],
                $userinfo['mail'],
                $userinfo['grps'],
            ]
        );
    }

    /**
     * Validate SSO token/nonce and signature
     *
     * @param string $sig
     * @param string $sso
     * @return bool
     */
    protected function validateToken($sig, $sso)
    {
        if (!isset($_COOKIE[self::TOKEN_COOKIE])) {
            return false;
        }

        $sso = urldecode($sso);
        $query = [];
        parse_str(base64_decode($sso), $query);

        $comp = hash_hmac('sha256', $sso, $this->getConf('sso_secret'));

        return $comp === $sig && $query['nonce'] === $_COOKIE[self::TOKEN_COOKIE];
    }

    /**
     * Checks if the provider's response contains all required data
     *
     * @param array $response
     * @return bool
     */
    protected function validateResponse($response)
    {
        foreach (self::REQUIRED_USERINFO as $key) {
            if (empty($response[$key])) return false;
        }
        return true;
    }
}
