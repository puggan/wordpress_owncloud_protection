<?php
/**
* @package Owncloud Protection
* @author Puggan
* @version 1.0.0-20150201
**/
/*
Plugin Name: Owncloud Protection
Plugin URI: https://github.com/puggan/wordpress_owncloud_protection
Description: Use owncloud as permission check for pages
Version: 1.0.0-20150201
Author: Puggan
Author URI: http://blog.puggan.se
Text Domain: owncloud_protection
Domain Path: /lang
*/

// Set a constant for current version
define("OWNCLOUD_PROTECTION_PLUGIN_VERSION", '1.0.0');

define("DEFAULT_OPTION_OWNCLOUD_BLOCK", FALSE);
define("DEFAULT_OPTION_LOGIN_URL", "/?redirect_url=%1");
define("DEFAULT_OPTION_OWNCLOUD_URL", "/index.php/apps/files/");
define("DEFAULT_OPTION_OWNCLOUD_DATABASE_PREFIX", "oc_");

require_once __DIR__ . '/oc_protect.php';
require_once __DIR__ . '/Owncloud_User_Status_Widget.php';


	// create an instance of this plugins class, and store it in globals
	$GLOBALS['oc_protect'] = new oc_protect();

	// amd run its init()
	$GLOBALS['oc_protect']->init();
