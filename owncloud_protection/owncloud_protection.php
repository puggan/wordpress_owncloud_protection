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
*/

// Set a constant for current version
define("OWNCLOUD_PROTECTION_PLUGIN_VERSION", '1.0.0');

define("DEFAULT_OPTION_OWNCLOUD_BLOCK", FALSE);
define("DEFAULT_OPTION_LOGIN_URL", "/?redirect_url=%1");
define("DEFAULT_OPTION_OWNCLOUD_URL", "/index.php/apps/files/");

class oc_protect
{
	// define class variables
	public $settings = NULL;
	public $oc_cookie_name = NULL;
	public $user_id = NULL;
	public $admin = NULL;
	public $groups = NULL;
	public $error = NULL;

	// class constuctor that fetchs wordpress settings and owncloud userid and groups
	function __construct()
	{
		global $wpdb;

		// fetch global settings
		$this->settings['global_block'] = get_option("oc_protect_global_block", DEFAULT_OPTION_OWNCLOUD_BLOCK);
		$this->settings['login_oc_url'] = get_option("oc_protect_login_url", DEFAULT_OPTION_LOGIN_URL);
		$this->settings['oc_url'] = get_option("oc_protect_url", DEFAULT_OPTION_OWNCLOUD_URL);

		// look for a owncloud session cookie
		foreach(array_keys($_COOKIE) AS $cookie_key)
		{
			// the starts with "oc", short for owncloud
			if(substr($cookie_key, 0, 2) == "oc")
			{
				// store name, and stop looking
				$this->oc_cookie_name = $cookie_key;
				break;
			}
		}

		// if no owncloud cookie
		if(!$this->oc_cookie_name)
		{
			// then we can't do anything more
			$this->error = "No oc-cookie found";
			return;
		}

		// store current session id, incase we alredy have a session started
		$old_session_id = session_id();

		// if session is started
		if($old_session_id)
		{
			// turn off current session
			session_write_close();
		}

		// change session to the one found in cookie
		session_id($_COOKIE[$this->oc_cookie_name]);

		// use cookiename as session name, and store the old one
		$old_session_name = session_name($this->oc_cookie_name);

		// start the owncloud session
		session_start();

		// if the owncloud session have a user_id
		if(isset($_SESSION['user_id']) AND $_SESSION['user_id'])
		{
			// remember that user_id
			$this->user_id = $_SESSION['user_id'];
		}
		else
		{
			// then we not logged in, preper canceling
			$this->error = "No user_id found";
		}

		// close owncloud session
		session_write_close();

		// if there was an session started before
		if($old_session_id)
		{
			// resote the old session
			session_id($old_session_id);
			session_name($old_session_name);
			session_start();
		}

		// if we had an error, cancel now when session is restored
		if($this->error)
		{
			return;
		}

		// ask database for the groups of the current owncloud user
		$oc_groups = $wpdb->get_col($wpdb->prepare("SELECT gid FROM oc_group_user WHERE uid = %s", $this->user_id));

		// if we found groups
		if($oc_groups)
		{
			// set array keys to same as value, for easy lookup
			$this->groups = array_combine($oc_groups, $oc_groups);
		}
		else if($wpdb->last_error)
		{
			// set groups to no groups
			$this->groups = array();

			// copy error message
			$this->error = "DB-error: " . $wpdb->last_error;
		}
		else
		{
			// set groups to no groups
			$this->groups = array();
		}

		// Check if user is admin
		if($this->user_id == 'root' OR isset($this->groups['admin']))
		{
			$this->admin = TRUE;
		}
	}

	/**
	 * Check if we are a member of the given target
	 *
	 * @param $target group name, or username prepend with "@"
	 * @return boolean
	 **/
	public function check_permission($target)
	{
		// no user => nor permissions
		if(!$this->user_id) return FALSE;

		// target is a user?
		if(substr($target, 0, 1) == '@')
		{
			// same user as logged in user?
			return (substr($target, 1) == $this->user_id);
		}

		// target is a group, are current user a member of that group?
		return isset($this->groups[$target]);
	}

	/**
	 * Check if we are a member of any of the given targets
	 *
	 * @param $targets list of target, array, space-separated string, or comma-separated string
	 * @return boolean
	 **/
	public function check_permission_list($targets)
	{
		// no user => nor permissions
		if(!$this->user_id) return FALSE;

		// list is in string format?
		if(!is_array($targets))
		{
			// convert to array, spliting on " " and ","
			$targets = explode(" ", str_replace(",", " ", $targets));
		}

		// for each targets
		foreach($targets as $current_target)
		{
			// trim extra whitespaces like rowbreaks and tabs
			$current_target = trim($current_target);

			// ignore empty targets, explode makes empty targets when useing double separators liek ", "
			if(!$current_target) continue;

			// check the current target
			if($this->check_permission($current_target))
			{
				// if any target is allowd, then we are done
				return TRUE;
			}
		}

		// all targets failed, deny
		return FALSE;
	}

	/**
	 * Connect our function to the wordpress triggers
	 **/
	public function init()
	{
		// allow auto login as owncloud user
		add_filter('determine_current_user', array($this, 'set_current_user'), 30);

		// sync logout with owncloud
		add_action('clear_auth_cookie', array($this, 'clear_cookie'));
		add_action('wp_logout', array($this, 'logout'));

		// check the global block, redirect to owncloud login if not logged in
		add_action('init', array($this, 'global_block_test'));

		// add windget
		add_action('widgets_init', array($this, 'register_widgets'));

		// add plugin setting page
		add_action('admin_menu', array($this, 'register_setting_page'));

		// add permission fields to edit page
		add_action('add_meta_boxes_page', array($this, 'register_meta_box'));
		add_action('save_post', array($this, 'save_page_permissions'));

		// filter out post that user don't are allowed to se
		add_filter('posts_results', array($this, 'filter_posts'), 10, 2);
		add_filter('wp_nav_menu_objects', array($this, 'filter_menu'));
		add_action('post_edit_form_tag', array($this, 'filter_edit_page'));
	}

	/**
	 * Tell wordpress we want to be logged in as the owncloud user
	 *
	 * @param $current_user_id from determine_current_user filter
	 * @return the wordpress-id of the owncloud user, or just pass the $current_user_id forward
	 **/
	public function set_current_user($current_user_id)
	{
		// if we not loged in as a owncloud user
		if(!$this->user_id)
		{
			// pass the old value forward
			return $current_user_id;
		}

		// lookup the wordpress user for the current owncloud user
		$wanted_user = get_user_by('login', $this->user_id);

		// if we didn't find a wordpress user
		if(!$wanted_user OR !is_a($wanted_user, 'WP_User'))
		{
			// define our information for a new user
			$new_user = array();
			$new_user['user_login'] = $this->user_id;
			$new_user['role'] = 'editor';

			// make owncloud admins wordpress admins
			if($this->admin)
			{
				$new_user['role'] = 'administrator';
			}

			// add as wordpress user
			$wanted_user = wp_insert_user($new_user);

			// if we didn't get a new user
			if(!$wanted_user OR !is_a($wanted_user, 'WP_User'))
			{
				// pass the old value forward
				return $current_user_id;
			}
		}

		// if the user we want to be logged in as, is'n the same user that wordpress remember are logged in
		if($wanted_user->ID != $current_user_id)
		{
			// tell wordpress to remember the owncloud user insted
			wp_set_auth_cookie($wanted_user->ID, TRUE, TRUE);
		}

		// pass the owncloud users id forward
		return $wanted_user->ID;
	}

	/**
	 * clear owncloud session when wordpress triggers clear_auth_cookie
	 **/
	public function clear_cookie()
	{
		// if we don't know any owncloud cookies
		if(!$this->oc_cookie_name)
		{
			// there is nothing todo
			return;
		}

		// if there alredy is a seesion started
		if(session_id())
		{
			// close that session
			session_write_close();
		}

		// open the owncloud session
		session_id($_COOKIE[$this->oc_cookie_name]);
		session_name($this->oc_cookie_name);
		session_start();

		// destroy the owncloud session
		session_destroy();

		// clear the owncloud cookie
		setcookie($this->oc_cookie_name, "", time()-3600);
	}

	/**
	 * overide wordpress wp_logout
	 **/
	public function logout()
	{
		// if we have a url to the owncloud loginpage
		if($this->settings['login_oc_url'])
		{
			// fetch the wordpress home url, so we know where to redirect back to after next login
			$home_url_parts = parse_url(home_url());

			// tell browser to goto to the owncloud loginpage, with a reference to the wordpress home uri
			header("Location: " . str_replace("%1", "{$home_url_parts['path']}?{$home_url_parts['query']}", $this->settings['login_oc_url']));

			// kill wordpress, using http-code 307, for temporary redirect
			wp_die("Logged out from owncloud.", "Logged out", array("response" => 307));
		}
		// if we have not owncloud login page
		else
		{
			// kill wordpress, using http-code 200, for "ok", as this wasn't a error
			wp_die("Logged out from owncloud", "Logged out", array("response" => 200));
		}
	}

	/**
	 * triger the global block if needed, triggerd by wordpress init
	 **/
	public function global_block_test()
	{
		// if no owncloud user, and global_block is activated
		if(!$this->user_id AND $this->settings['global_block'])
		{
			// if we have the url to the owncloud login
			if($this->settings['login_oc_url'])
			{
				// tell browser to go to the owncloud loginpage, whit a reference back to the page we tried to visit
				header("Location: " . str_replace("%1", $_SERVER['REQUEST_URI'], $this->settings['login_oc_url']));

				// kill wordpress, using http-code 307, for temporary redirect
				wp_die("Permission denied, global_block for non owncloud users. " . $this->error, "Permission denied", array("response" => 307));
			}
			else
			{
				// kill wordpress, using http-code 403, for "permission denied"
				wp_die("Permission denied, global_block for non owncloud users. " . $this->error, "Permission denied", array("response" => 403));
			}

			// make sure the execution dies, in case wp_die() failed
			die();
		}
	}

	/**
	 * Register widget at wordpress 'widgets_init'-trigger
	 **/
	public function register_widgets()
	{
		register_widget( 'Owncloud_User_Status_Widget' );
	}

	/**
	 * Register metabox at wordpress 'add_meta_boxes_page'-trigger
	 **/
	public function register_meta_box()
	{
		add_meta_box("oc_page_permission", "Owncloud permissions", array($this, "meta_box_page_edit"), 'page', 'side');
	}

	/**
	 * Register setting page at wordpress 'admin_menu'-trigger
	 **/
	public function register_setting_page()
	{
		add_submenu_page("options-general.php", "Owncloud protection settings", "Owncloud", 'manage_options', "owncloud-prot", array($this, "setting_page"));
	}

	/**
	 * Content for meta-box at edit-page
	 *
	 * @param $current_post the post getting edited, see function add_meta_box()
	 **/
	public function meta_box_page_edit($current_post)
	{
		// fetch current values
		$read_permission = get_post_meta($current_post->ID, '_oc_read_permission', TRUE);
		$edit_permission = get_post_meta($current_post->ID, '_oc_edit_permission', TRUE);

		// add a nonce, as it was a recomendated protection
		wp_nonce_field('oc_permission', 'oc_permission_nonce');

		// add a input for read permission
		echo "<div>";
		echo '<label for="oc_read_permission">Read permission:</label> ';
		echo '<input type="text" id="oc_read_permission" name="oc_read_permission" value="' . esc_attr($read_permission) . '" />';
		echo "</div>";

		// add a input for edit permission
		echo "<div>";
		echo '<label for="oc_edit_permission">Edit permission:</label> ';
		echo '<input type="text" id="oc_edit_permission" name="oc_edit_permission" value="' . esc_attr($edit_permission) . '" />';
		echo "</div>";
	}

	/**
	 * fetch our extra filed from edit page
	 *
	 * @param $page_id the id of the page that was edited, see action 'save_post'
	 **/
	public function save_page_permissions($page_id)
	{
		// check for posible errors and verify that its a real permitted save page
		if(defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) return;
		if(!isset($_POST['oc_permission_nonce'])) return;
		if(!isset($_POST['oc_read_permission'])) return;
		if(!isset($_POST['oc_edit_permission'])) return;
		if(!wp_verify_nonce($_POST['oc_permission_nonce'], 'oc_permission')) return;
		if(isset($_POST['post_type']) && 'page' != $_POST['post_type']) return;
		if(!current_user_can('edit_page', $page_id)) return;

		// Sanitize user input.
		$read_permission = sanitize_text_field($_POST['oc_read_permission']);
		$edit_permission = sanitize_text_field($_POST['oc_edit_permission']);

		// Update the meta field in the database.
		update_post_meta($page_id, '_oc_read_permission', $read_permission);
		update_post_meta($page_id, '_oc_edit_permission', $edit_permission);
	}


	/**
	 * print setting-page added by add_submenu_page()
	 **/
	public function setting_page()
	{
		// Add title/header
		echo '<h2>Owncloud protection settings</h2>';

		// show error if permission deined
		if(!current_user_can('manage_options'))
		{
			wp_die(__('You do not have sufficient permissions to access this page.'));
		}

		// Did user press the save-button?
		if(isset($_POST['save']))
		{
			// check nonce
			if(wp_verify_nonce($_POST['owncloud_prot_settings_nonce'], 'owncloud-prot-settings'))
			{
				// variable to store results
				$results = array();
				// Save all fields
				$results[] = update_option("oc_protect_global_block", $_POST["oc_protect_global_block"]);
				$results[] = update_option("oc_protect_login_url", $_POST["oc_protect_login_url"]);
				$results[] = update_option("oc_protect_url", $_POST["oc_protect_url"]);

				//count changes
				$changes = array_sum($results);

				// if chnages was mage
				if($changes)
				{
					// Reload setting
					$this->settings['global_block'] = get_option("oc_protect_global_block", DEFAULT_OPTION_OWNCLOUD_BLOCK);
					$this->settings['login_oc_url'] = get_option("oc_protect_login_url", DEFAULT_OPTION_LOGIN_URL);
					$this->settings['oc_url'] = get_option("oc_protect_url", DEFAULT_OPTION_OWNCLOUD_URL);

					// Tell user we saved the fields
					echo "<div class='updated'><p><strong>Settings saved, {$changes} changed</strong></p></div>";
				}
				else
				{
					// Tell user we tried to saved the fields
					echo "<div class='updated'><p><strong>Saved, but no changes was made</strong></p></div>";
				}
			}
		}

		// Add form
		echo '<form method="post" action="">';

		// add a nonce field for extra protection
		wp_nonce_field( 'owncloud-prot-settings', 'owncloud_prot_settings_nonce' );

		// add option for global_block, allow guest or not
		echo "<div>";
		echo "<label for='oc_protect_global_block' style='width: 100px; display: inline-block;'>Guests</label>";
		echo "<select name='oc_protect_global_block'>";
		echo "<option value='0'" . ($this->settings['global_block'] ? '' : " selected='selected'") . ">Allow guests</option>";
		echo "<option value='1'" . ($this->settings['global_block'] ? " selected='selected'" : '') . ">Only loggedin users</option>";
		echo "</select>";
		echo "</div>";

		// add field for login url
		echo "<div>";
		echo "<label for='oc_protect_login_url' style='width: 100px; display: inline-block;'>Login url</label>";
		echo "<input name='oc_protect_login_url' value='" . esc_attr($this->settings['login_oc_url']) . "' />";
		echo "</div>";

		// add field for owncloud url
		echo "<div>";
		echo "<label for='oc_protect_url' style='width: 100px; display: inline-block;'>App url</label>";
		echo "<input name='oc_protect_url' value='" . esc_attr($this->settings['oc_url']) . "' />";
		echo "</div>";

		// add button
		echo "<div>";
		echo "<input type='submit' name='save' class='button-primary' value='Save' />";
		echo "</div>";

		// end form
		echo "</form>";
	}

	/**
	 * Adds a permission check before post/pages are deliverd.
	 * using the filter 'posts_results'
	 *
	 * @param $posts the list of posts, see filter 'posts_results'
	 * @param $query_object the query that generated the list of post, see filter 'posts_results'
	 * @return filtered list of @posts
	 **/
	public function filter_posts($posts, $query_object)
	{
		// don't filter for owncloud admins
		if(!$this->admin)
		{
			// check all posts, one by one
			foreach($posts as $index => $current_post)
			{
				// only filter pages
				if($current_post->post_type == 'page')
				{
					// fetch read permissons for the current page
					$read_permission = get_post_meta($current_post->ID, '_oc_read_permission', TRUE);

					// if page have readpermissions set
					if($read_permission)
					{
						// do a permisson check against that list of permitted targets
						if(!$this->check_permission_list($read_permission))
						{
							// remove page from list, if owncloud user not in the list of permitted targets
							unset($posts[$index]);
						}
					}
				}
			}
		}

		// pass the rest of the post forward
		return $posts;
	}

	/**
	 * Adds a permission check before menus are deliverd.
	 * using the filter 'wp_nav_menu_objects'
	 *
	 * @param $menu the list of menu options, see filter 'wp_nav_menu_objects'
	 * @return filtered list of @posts
	 **/
	public function filter_menu($menu)
	{
		// don't filter for owncloud admins
		if(!$this->admin)
		{
			// check all menu options, one by one
			foreach($menu as $index => $current_menu)
			{
				// only filter menuoptions pointing to pages
				if($current_menu->object == 'page')
				{
					// fetch read permissons for the current page
					$read_permission = get_post_meta($current_menu->object_id, '_oc_read_permission', TRUE);

					// if page have readpermissions set
					if($read_permission)
					{
						// do a permisson check against that list of permitted targets
						if(!$this->check_permission_list($read_permission))
						{
							// remove menu option from list, if owncloud user not in the list of permitted targets
							unset($menu[$index]);
						}
					}
				}
			}
		}

		// pass the rest of the menu options forward
		return $menu;
	}

	/**
	 * disable edit page when user don't have permission
	 * using action 'post_edit_form_tag'
	 *
	 * @param $current_post the post that someone tries to edit
	 **/
	public function filter_edit_page($current_post)
	{
		// Allow admins
		if($this->admin) return TRUE;

		// Only filter pages
		if($current_post->post_type != 'page') return TRUE;

		// fetch list of edit permissons
		$edit_permission = get_post_meta($current_post->ID, '_oc_edit_permission', TRUE);

		// if edit permissions not set, use read permissions
		if(!$edit_permission) $edit_permission = get_post_meta($current_post->ID, '_oc_read_permission', TRUE);

		// Allow edit if page have neither edit or read permissons
		if(!$edit_permission) return TRUE;

		// Allow if owncloud user in allowed targets
		if($this->check_permission_list($edit_permission)) return TRUE;

		// Disable edit if there was no reason to allow edit, using code 403 'Permission Denied'
		wp_die("Permission denied, you not allowed to edit this page.", "Permission denied", array("response" => 403));
	}
}

/**
 * Widget for showing info about Owncloud user and link to files
 **/
class Owncloud_User_Status_Widget extends WP_Widget
{
	/**
	 * register widget name when the widgets are created
	 **/
	public function __construct()
	{
		parent::__construct(
			'owncloud_user_status_widget', // Base ID
			'Owncloud user status', // Name
			array('description' => 'Show status for loged in owncloud user', ) // Args
		);
	}

	/**
	 * widget html output
	 *
	 * @param $widget_args template parts like 'before_title' and 'after_widget'
	 * @param $instance stored widget options
	 **/
	public function widget($widget_args, $instance)
	{
		// use temple-part before_widget
		echo $widget_args['before_widget'];

		// write title, using template parts
		echo "{$widget_args['before_title']}Owncloud user{$widget_args['after_title']}";

		// check if we are logged in
		if($GLOBALS['oc_protect']->user_id)
		{
			// check option for show_username
			if(isset($instance['show_username']) AND $instance['show_username'])
			{
				// show username
				echo "<p>User: {$GLOBALS['oc_protect']->user_id}</p>";
			}

			// check option for show_groups
			if(isset($instance['show_groups']) AND $instance['show_groups'])
			{
				// and owncloud user is a member of at least one group
				if($GLOBALS['oc_protect']->groups)
				{
					// show groups
					echo "<p>Groups: " . implode(", ", $GLOBALS['oc_protect']->groups) . "</p>";
				}
				else
				{
					// show error, use italic, to make it more noticable that its not a group named none
					echo "<p>Groups: <i>(none)</i></p>";
				}
			}

			// check option for show_link, and if we have a posible url to show
			if(isset($instance['show_link']) AND $instance['show_link'] AND $GLOBALS['oc_protect']->settings['oc_url'])
			{
				// show link
				echo "<p><a href='{$GLOBALS['oc_protect']->settings['oc_url']}'>Show filelist</a></p>";
			}
		}
		// if we aren't logged in
		else
		{
			// write error insted of user
			echo "<p>Not logged in</p>";

			// if we have a url to loginpage
			if($GLOBALS['oc_protect']->settings['login_oc_url'])
			{
				// add a reference back to current page to login url
				$login_url = str_replace("%1", $_SERVER['REQUEST_URI'], $GLOBALS['oc_protect']->settings['login_oc_url']);

				// write link to login url
				echo "<p><a href='{$login_url}'>Login</a></p>";
			}
		}

		// if option for debug information is turned on (off by default)
		if(isset($instance['show_debug']) AND $instance['show_debug'])
		{
			// and we visiting a page at the momment
			if(isset($GLOBALS['post']) AND $GLOBALS['post']->post_type == 'page')
			{
				// tell user what page we are on, using ID
				echo "<p>Page: {$GLOBALS['post']->ID}</p>";

				// make list for saving html of targets
				$permission_html['read'] = array();
				$permission_html['edit'] = array();

				// fetch list of allowed targets
				$permission['read'] = get_post_meta($GLOBALS['post']->ID, '_oc_read_permission', TRUE);
				$permission['edit'] = get_post_meta($GLOBALS['post']->ID, '_oc_edit_permission', TRUE);

				// do same things for both list, 'read' and 'edit'
				foreach(array('read', 'edit') as $ptype)
				{
					// convert space/comma-separeted string to array and loop throught all targets
					foreach(explode(" ", str_replace(",", " ", $permission[$ptype])) as $current_target)
					{
						// remove extra whitespaces
						$current_target = trim($current_target);

						// skip empty targets, creted by explode when using multiple separators like ", "
						if(!$current_target) continue;

						// check if owncloud user is a part of current target
						if($GLOBALS['oc_protect']->check_permission($current_target))
						{
							// add matching targets with bold
							$permission_html[$ptype][] = "<b>" . $current_target . "</b>";
						}
						else
						{
							// add non matching target as normal (none bold)
							$permission_html[$ptype][] = "<span>" . $current_target . "</span>";
						}
					}
				}

				// write both list as html
				echo "<p>Read: " . implode(", ", $permission_html['read']) . "</p>";
				echo "<p>Edit: " . implode(", ", $permission_html['edit']) . "</p>";
			}
		}

		// use temple-part after_widget
		echo $widget_args['after_widget'];
	}

	/**
	 * Print widget options form
	 **/
	public function form( $instance )
	{
		// create a list for what fields we need
		$fields = array();

		// define filed show_username
		$fields['username']['id'] = $this->get_field_id('show_username');
		$fields['username']['name'] = $this->get_field_name( 'show_username' );
		$fields['username']['title'] = "Show username";
		$fields['username']['value'] = (isset($instance['show_username']) ? $instance['show_username'] : TRUE);

		// define filed show_groups
		$fields['groups']['id'] = $this->get_field_id('show_groups');
		$fields['groups']['name'] = $this->get_field_name( 'show_groups' );
		$fields['groups']['title'] = "Show groups";
		$fields['groups']['value'] = (isset($instance['show_groups']) ? $instance['show_groups'] : TRUE);

		// define filed show_link
		$fields['link']['id'] = $this->get_field_id('show_link');
		$fields['link']['name'] = $this->get_field_name( 'show_link' );
		$fields['link']['title'] = "Show link";
		$fields['link']['value'] = (isset($instance['show_link']) ? $instance['show_link'] : TRUE);

		// define filed show_debug
		$fields['debug']['id'] = $this->get_field_id('show_debug');
		$fields['debug']['name'] = $this->get_field_name( 'show_debug' );
		$fields['debug']['title'] = "Debug info";
		$fields['debug']['value'] = (isset($instance['show_debug']) ? $instance['show_debug'] : FALSE);

		// foreach field
		foreach($fields as $field)
		{
			// create checked-html if selected
			$checked = $field['value'] ? " checked='checked'": "";

			// print html for field
			echo <<<HTML
		<p>
			<label for="{$field['id']}">{$field['title']}</label>
			<input class="widefat" id="{$field['id']}" name="{$field['name']}" type="checkbox" value="1" {$checked} />
		</p>
HTML;
		}
	}

	/**
	 * store widget settings
	 *
	 * @param $new_instance settings as they where when user clicked save
	 * @param $old_instance settings as they where when user got form
	 * @return list of settings to save
	 **/
	public function update($new_instance, $old_instance)
	{
		// convert posted checkbox to booleans
		$instance = array(
			'show_username' => isset($new_instance['show_username']),
			'show_groups' => isset($new_instance['show_groups']),
			'show_link' => isset($new_instance['show_link']),
			'show_debug' => isset($new_instance['show_debug']),
		);

		// store the boolean settings
		return $instance;
	}
}

	// create an instance of this plugins class, and store it in globals
	$GLOBALS['oc_protect'] = new oc_protect();

	// amd run its init()
	$GLOBALS['oc_protect']->init();
