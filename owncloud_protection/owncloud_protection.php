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

class oc_protect
{
	public $settings = NULL;
	public $oc_cookie_name = NULL;
	public $user_id = NULL;
	public $groups = NULL;
	public $error = NULL;
	
	function __construct()
	{
		global $wpdb;

		/// TODO: load settings
		
		// Fake settings
		{
			$this->settings['global block'] = TRUE;
			$this->settings['oc url'] = "/";
		}
		
		$old_session = session_id();

		foreach(array_keys($_COOKIE) AS $cookie_key)
		{
			if(substr($cookie_key, 0, 2) == "oc")
			{
				$this->oc_cookie_name = $cookie_key;
				break;
			}
		}

		if(!$this->oc_cookie_name)
		{
			$this->error = "No oc-cookie found";
			return;
		}

		if($old_session)
		{
			session_write_close();
		}
		session_id($_COOKIE[$this->oc_cookie_name]);
		session_start();

		if(isset($_SESSION['user_id']) AND $_SESSION['user_id'])
		{
			$this->user_id = $_SESSION['user_id'];
		}
		else
		{
			$this->error = "No user_id found";
		}

		session_write_close();

		if($old_session)
		{
			session_id($old_session);
			session_start();
		}
		
		if($this->error)
		{
			return;
		}

		$oc_groups = $wpdb->get_col($wpdb->prepare("SELECT gid FROM oc_group_user WHERE uid = %s", $oc_user_id));
		$this->groups = array_combine($oc_groups, $oc_groups);
	}
	
	public function init()
	{
		add_action('init', array($this, 'global_block_test'));
	}
	
	public function global_block_test()
	{
		if(!$this->user_id AND $this->settings['global block'])
		{
			if($this->settings['oc url'])
			{
				header("Location: {$this->settings['oc url']}");
				wp_die("Permission denied, global block for non owncloud users. " . $this->error, "Permission denied", array("response" => 307));
				die();
			}
			else
			{
				wp_die("Permission denied, global block for non owncloud users. " . $this->error, "Permission denied", array("response" => 403));
				die();
			}
		}
	}
}

	$GLOBALS['oc_protect'] = new oc_protect();
	
	$GLOBALS['oc_protect']->init();
