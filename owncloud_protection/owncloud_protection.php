<?php
/**
 * @package Owncloud Protection
 * @author Puggan
 * @version 0.0.1-20150128
 */
/*
Plugin Name: Owncloud Protection
Description: Use owncloud as permission check for pages
Version: 0.0.1-20150128
Author: Puggan
Author URI: http://blog.puggan.se
*/

DEFINE("OWNCLOUD_PROTECTION_PLUGIN_VERSION", '0.0.1');

	function oc_init()
	{
		global $wpdb;

		$old_session = session_id();
		$oc_session = NULL;

		foreach(array_keys($_COOKIE) AS $cookie_key)
		{
			if(substr($cookie_key, 0, 2) == "oc")
			{
				$oc_session = $cookie_key;
				break;
			}
		}

		if(!$oc_session)
		{
			/// TODO: get settings for login-page-url
			header("Location: /");
			die("No oc-cookie found");
		}

		if($old_session)
		{
			session_write_close();
		}
		session_id($_COOKIE[$oc_session]);
		session_start();

		if(!isset($_SESSION['user_id']) OR !$_SESSION['user_id'])
		{
			/// TODO: get settings for login-page-url
			header("Location: /");
			die("No user_id found");
		}

		$oc_user_id = $_SESSION['user_id'];
		session_write_close();

		if($old_session)
		{
			session_id($old_session);
			session_start();
		}

		$oc_groups = $wpdb->get_col($wpdb->prepare("SELECT gid FROM oc_group_user WHERE uid = %s", $oc_user_id));
		$oc_groups = array_combine($oc_groups, $oc_groups);

		$GLOBALS['oc'] = array('user_id' => $oc_user_id, 'groups' => $oc_groups);
	}

	oc_init();
