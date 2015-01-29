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

		$oc_groups = $wpdb->get_col($wpdb->prepare("SELECT gid FROM oc_group_user WHERE uid = %s", $this->user_id));

		$this->groups = array_combine($oc_groups, $oc_groups);
	}
	
	public function init()
	{
		add_action('init', array($this, 'global_block_test'));
		add_action('widgets_init', array($this, 'register_widgets'));
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
	
	public function register_widgets()
	{
		register_widget( 'Owncloud_User_Status_Widget' );
	}
}

class Owncloud_User_Status_Widget extends WP_Widget
{
	public function __construct()
	{
		parent::__construct(
			'owncloud_user_status_widget', // Base ID
			'Owncloud user status', // Name
			array( 'description' => 'Show status for loged in owncloud user', ) // Args
		);
	}

	public function widget( $widget_args, $instance )
	{
		extract( shortcode_atts( array(
			'show_username' => TRUE,
			'show_groups' => TRUE,
			'show_link' => TRUE,
		), $instance ) );

		echo $widget_args['before_widget'];

		if($show_username)
		{
			echo "<p>User: {$GLOBALS['oc_protect']->user_id}</p>";
		}
		
		if($show_groups)
		{
			if($GLOBALS['oc_protect']->groups)
			{
				echo "<p>Groups: " . implode(", ", $GLOBALS['oc_protect']->groups) . "</p>";
			}
			else
			{
				echo "<p>Groups: (none)</p>";
			}
		}
		
		if($show_link)
		{
			echo "<p><a href='{$GLOBALS['oc_protect']->settings['oc url']}'>Show filelist</a></p>";
		}
		
		echo $widget_args['after_widget'];
	}

 	public function form( $instance )
	{
		$fields = array();
		$fields['username']['id'] = $this->get_field_id('show_username');
		$fields['username']['name'] = $this->get_field_name( 'show_username' );
		$fields['username']['title'] = "Show username";
		$fields['username']['value'] = (isset($instance['show_username']) ? $instance['show_username'] : TRUE);

		$fields['groups']['id'] = $this->get_field_id('show_groups');
		$fields['groups']['name'] = $this->get_field_name( 'show_groups' );
		$fields['groups']['title'] = "Show groups";
		$fields['groups']['value'] = (isset($instance['show_groups']) ? $instance['show_groups'] : TRUE);

		$fields['link']['id'] = $this->get_field_id('show_link');
		$fields['link']['name'] = $this->get_field_name( 'show_link' );
		$fields['link']['title'] = "Show link";
		$fields['link']['value'] = (isset($instance['show_link']) ? $instance['show_link'] : TRUE);

		foreach($fields as $field)
		{
			$checked = $field['value'] ? " checked='checked'": "";
			echo <<<HTML
		<p>
			<label for="{$field['id']}">{$field['title']}</label>
			<input class="widefat" id="{$field['id']}" name="{$field['name']}" type="checkbox" value="1" {$checked} />
		</p>
HTML;
		}
	}

	public function update( $new_instance, $old_instance )
	{
		$instance = array(
			'show_username' => ((int) $new_instance['show_username']),
			'show_groups' => ((int) $new_instance['show_groups']),
			'show_link' => ((int) $new_instance['show_link']),
		);
		return $instance;
	}
}

	$GLOBALS['oc_protect'] = new oc_protect();
	$GLOBALS['oc_protect']->init();
