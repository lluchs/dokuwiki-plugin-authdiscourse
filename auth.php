<?php
// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

/**
 * Discourse authentication backend
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Lukas Werling <lukas@lwrl.de>
 */
class auth_plugin_authdiscourse extends DokuWiki_Auth_Plugin {
    private $sso_secret, $sso_url;
    private $login_url;
    private $nonce, $prev_nonce;

    public function __construct() {
        parent::__construct();

        $this->success = true;
        $this->cando['external'] = true;
        $this->cando['logoff'] = true;

        global $conf;
        $cfg = $conf['plugin']['authdiscourse'];
        if (empty($cfg['sso_secret']) || empty($cfg['sso_url'])) {
            $this->success = false;
        } else {
            $this->sso_secret = $cfg['sso_secret'];
            $this->sso_url = $cfg['sso_url'];
        }
        // We need to set this cookie early, as the login URL will only be
        // requested during rendering. This also ensures that the nonce stays
        // valid for only exactly one request.
        // Note: This would probably be better in the session, but I couldn't
        // get that to work.
        list($prev_nonce, $mac) = explode(';', $_COOKIE['authdiscourse_nonce']);
        if (!empty($mac) && hash_equals(hash_hmac('sha256', $prev_nonce, $this->sso_secret), $mac))
            $this->prev_nonce = $prev_nonce;
        $this->nonce = base64_encode(random_bytes(18));
        setcookie('authdiscourse_nonce', $this->nonce.';'.hash_hmac('sha256', $this->nonce, $this->sso_secret), array('httponly' => true));
    }

    public function logOff() {
        @session_start();
        session_destroy();
    }

    public function trustExternal($user, $pass, $sticky=false) {
        global $USERINFO;
        // We don't use the login form, so $user and $pass will never be set.

        if (empty($_SESSION['authdiscourse_login'])) {
            if (!$this->checkSSO()) {
                return false;
            }
        }

        // User is already logged-in or successfully authenticated now.
        $login = $_SESSION['authdiscourse_login'];

        $USERINFO['name'] = $login['username'];
        $USERINFO['mail'] = $login['email'];
        $groups = explode(',', $login['groups']);
        $groups[] = 'user';
        if ($login['admin'] == 'true') $groups[] = 'admin';
        if ($login['moderator'] == 'true') $groups[] = 'moderator';
        $USERINFO['grps'] = $groups;

        $_SERVER['REMOTE_USER']                = $login['external_id'];
        $_SESSION[DOKU_COOKIE]['auth']['user'] = $login['external_id'];
        $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;

        return true;
    }

    // Checks SSO data after redirect from the SSO server.
    private function checkSSO() {
        // Are we returning from the SSO server?
        if (!empty($_GET) && isset($_GET['sso'])){
            @session_start();
            $sso = urldecode($_GET['sso']);
            $sig = $_GET['sig'];

            // validate sso
            $new_sig = hash_hmac('sha256', $sso, $this->sso_secret);
            if (!hash_equals(hash_hmac('sha256', $sso, $this->sso_secret), $sig)) {
                msg($this->getLang('sso_failed'), -1);
                return false;
            }

            $query = array();
            parse_str(base64_decode($sso), $query);

            // verify nonce with generated nonce
            if ($query['nonce'] !== $this->prev_nonce) {
                msg($this->getLang('sso_failed'), -1);
                return false;
            }

            msg($this->getLang('sso_success'), 1);

            // login user
            $_SESSION['authdiscourse_login'] = $query;
            return true;
        }
        return false;
    }

    // Returns the external SSO login URL.
    public function getLoginURL() {
        if (empty($this->login_url))
            $this->login_url =  $this->generateLoginURL();
        return $this->login_url;
    }

    // Generates a URL to the SSO server.
    private function generateLoginURL() {
        $payload =  base64_encode(http_build_query(array(
            'nonce' => $this->nonce,
            'return_sso_url' => "http://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]",
        )));
        $request = array(
            'sso' => $payload,
            'sig' => hash_hmac('sha256', $payload, $this->sso_secret),
        );
        return $this->sso_url.'?'.http_build_query($request);
    }
}
