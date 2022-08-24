<?php
/**
 * DokuWiki Plugin authdiscourse (Auth Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Anna Dabrowska <dokuwiki@cosmocode.de>
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

        $sig = $INPUT->str('sig');
        $sso = $INPUT->str('sso');

        // token in query string?
        if ($sig && $sso && $this->validateToken($sig, $sso)) {
            // get user info from response
            $ssoResponse = [];
            parse_str(base64_decode($sso), $ssoResponse);

            if (!$this->validateResponse($ssoResponse)) {
                msg($this->getLang('error_login'), -1);
                return false;
            }

            $username = $ssoResponse['username'];
            $mail = $ssoResponse['email'];
            $token = $ssoResponse['nonce'];
            $groups = !empty($ssoResponse['groups']) ? explode(',', $ssoResponse['groups']) : [];

            // user with this email exists? try login
            $found = $this->retrieveUsers(0, 1, ['mail' => '^' . str_replace('.', '\.', $mail) . '$']);
            if ($found) {
                $userinfo = $found[key($found)];
                $username = key($found);
                // update user
                $this->modifyUser($username, $this->createUserinfo($username, $mail, $groups, $userinfo['name']));
                return $this->tokenLogin($username, $userinfo, $token);
            }

            // otherwise register and log in a new user
            $userinfo = $this->createUserinfo($username, $mail, $groups);
            if (!$this->addUser($userinfo)) {
                msg($this->getLang('error_login'), -1);
                return false;
            }
            return $this->tokenLogin($username, $userinfo, $token);
        }

        // token in cookie?
        if (
            $INPUT->str('do') !== 'logout' &&
            !empty($_COOKIE[self::TOKEN_COOKIE]) &&
            $_SESSION[DOKU_COOKIE]['auth']['user']
        ) {
            return $this->tokenLogin(
                $_SESSION[DOKU_COOKIE]['auth']['user'],
                $_SESSION[DOKU_COOKIE]['auth']['info'],
                $_COOKIE[self::TOKEN_COOKIE]
            );
        }

        return false;
    }

    /**
     * Delete token cookie after logout
     */
    public function logOff()
    {
        parent::logOff();

        global $conf;
        $cookieDir = empty($conf['cookiedir']) ? DOKU_REL : $conf['cookiedir'];
        setcookie(
            self::TOKEN_COOKIE,
            '',
            time() - 3600 * 24,
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
     * Creates auth cookie, auth session and token cookie
     *
     * @param string $username
     * @param array $userinfo
     * @param $token
     * @return bool
     */
    protected function tokenLogin($username, $userinfo, $token)
    {
        global $USERINFO;

        $USERINFO['name'] = $username;
        $USERINFO['mail'] = $userinfo['mail'];
        $USERINFO['grps'] = $userinfo['grps'];

        $_SERVER['REMOTE_USER'] = $username;

        $secret = auth_cookiesalt(false, true);
        auth_setCookie($username, auth_encrypt($token, $secret), false);

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
     * Returns user info array
     *
     * @param string $username
     * @param string $mail
     * @param array $groups
     * @param string $name
     * @return array
     */
    protected function createUserinfo($username, $mail, $groups, $name = '')
    {
        global $conf;

        $userinfo['user'] = strtolower($username);
        $userinfo['mail'] = $mail;
        $userinfo['grps'] = array_merge([$conf['defaultgroup']], $groups);
        $userinfo['name'] = $name ?: $username;
        return $userinfo;
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
