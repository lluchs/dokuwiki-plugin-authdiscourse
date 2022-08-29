<?php
/**
 * DokuWiki Plugin authdiscourse (Action Component)
 */

class action_plugin_authdiscourse extends DokuWiki_Action_Plugin
{

    /**
     * Registers a callback function for a given event
     *
     * @param Doku_Event_Handler $controller DokuWiki's event controller object
     * @return void
     */
    public function register(Doku_Event_Handler $controller)
    {
        global $conf;
        if ($conf['authtype'] !== 'authdiscourse') return;

        $controller->register_hook('HTML_LOGINFORM_OUTPUT', 'BEFORE', $this, 'handle_loginform'); // old
        $controller->register_hook('FORM_LOGIN_OUTPUT', 'BEFORE', $this, 'handle_loginform'); // new

        $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'handle_dologin');
        $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'handle_dologout');
    }

    /**
     * Replaces login form with a button
     *
     * @param Doku_Event $event the form event
     * @param mixed $param unused
     * @return void
     */
    public function handle_loginform(Doku_Event $event, $param)
    {
        global $ID;
        $html = '<a href="' . wl($ID, ['do' => 'login']) . '" title="Discourse">';
        $html .= inlineSVG(__DIR__ . '/images/discourse.svg', 6000);
        $html .= '</a>';
        $form = $event->data;

        if (is_a($form, \dokuwiki\Form\Form::class)) {
            // New: clear the form
            for ($i = $form->elementCount(); $i > 0; $i--) {
                $form->removeElement($i - 1);
            }
            $form->addFieldsetOpen($this->getLang('login_with'))->addClass('plugin_authdiscourse');
            $form->addHTML($html);
            $form->addFieldsetClose();
        } else {
            // Old: replace form content
            $form->_content = [];
            $form->_content[] = form_openfieldset([
                '_legend' => $this->getLang('login_with'),
                'class' => 'plugin_authdiscourse',
            ]);
            $form->_content[] = $html;
            $form->_content[] = form_closefieldset();
        }
    }

    /**
     * Redirects to auth url
     *
     * @param Doku_Event $event
     * @param $param
     */
    public function handle_dologin(Doku_Event $event, $param)
    {
        if ($event->data !== 'login') {
            return;
        }

        global $auth;

        $endpoint = rtrim($this->getConf('sso_url'), '/');
        if (!preg_match('!/session/sso_provider$!', $endpoint)) $endpoint .= '/session/sso_provider';
        $secret = $this->getConf('sso_secret');
        $nonce = base64_encode(random_bytes(18));

        $payload = base64_encode(http_build_query(
            [
                'nonce' => $nonce,
                'return_sso_url' => DOKU_URL . 'doku.php',
            ], '', '&'
        ));
        $request = [
            'sso' => $payload,
            'sig' => hash_hmac('sha256', $payload, $secret),
        ];

        $auth->setTokenCookie($nonce);

        $url = $endpoint . '?' . http_build_query($request, '', '&');

        send_redirect($url);
    }

    /**
     * Take over logout, otherwise the logoff method will not be called.
     *
     * @param Doku_Event $event
     * @param $param
     */
    public function handle_dologout(Doku_Event $event, $param)
    {
        if ($event->data === 'logout') {
            auth_logoff();
        }
    }
}
