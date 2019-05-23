<?php

/**
 * DokuWiki Plugin authdiscourse (Action Component)
 *
 * Replaces the login form.
 * 
 * Based on the action.php from the authsaml plugin with the following
 * authors and license:
 * 
 * @author  Sixto Martin <sixto.martin.garcia@gmail.com>
 * @author  Andreas Aakre Solberg, UNINETT, http://www.uninett.no
 * @author  François Kooman
 * @author  Thijs Kinkhorst, Universiteit van Tilburg
 * @author  Jorge Hervás <jordihv@gmail.com>, Lukas Slansky <lukas.slansky@upce.cz>

 * @license GPL2 http://www.gnu.org/licenses/gpl.html
 * @link https://github.com/pitbulk/dokuwiki-saml
 */

// must be run within Dokuwiki
if (!defined('DOKU_INC'))
    die();

class action_plugin_authdiscourse extends DokuWiki_Action_Plugin
{

	/**
	 * Register event handlers
	 */
    public function register(Doku_Event_Handler $controller) {
        global $conf;
        if ($conf['authtype'] == 'authdiscourse') {
            $controller->register_hook('HTML_LOGINFORM_OUTPUT', 'BEFORE', $this, 'handle_login_form');
        }
    }

	function handle_login_form(&$event, $param)
	{
        global $auth, $lang;

        $loginurl = $auth->getLoginURL();

        // Replace the whole existing form as we can't handle username/password.
        $event->data->_content = array();
        $event->data->insertElement(0, '<a href="'.$loginurl.'" style="border: 5px solid; font-size: 200%; padding: 0.2em 0.5em;">'.$lang['btn_login'].'</a>');
	}

}
