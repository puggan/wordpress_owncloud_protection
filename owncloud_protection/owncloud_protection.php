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
	public $admin = NULL;
	public $groups = NULL;
	public $error = NULL;

	function __construct()
	{
		global $wpdb;

		$this->settings['global_block'] = get_option("oc_protect_global_block", TRUE);
		$this->settings['oc_url'] = get_option("oc_protect_url", "/index.php/apps/files/");
		$this->settings['login_oc_url'] = get_option("oc_protect_login_url", "/?redirect_url=%1");

		$old_session_id = session_id();

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

		if($old_session_id)
		{
			session_write_close();
		}
		session_id($_COOKIE[$this->oc_cookie_name]);
		$old_session_name = session_name($this->oc_cookie_name);
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

		if($old_session_id)
		{
			session_id($old_session_id);
			session_start($old_session_name);
		}

		if($this->error)
		{
			return;
		}

		$oc_groups = $wpdb->get_col($wpdb->prepare("SELECT gid FROM oc_group_user WHERE uid = %s", $this->user_id));

		$this->groups = array_combine($oc_groups, $oc_groups);

		if($this->user_id == 'root' OR isset($this->groups['admin']))
		{
			$this->admin = TRUE;
		}
	}

	public function check_permission($target)
	{
		if(!$this->user_id) return FALSE;

		if(substr($target, 0, 1) == '@')
		{
			return (substr($target, 1) == $this->user_id);
		}

		return isset($this->groups[$target]);
	}

	public function check_permission_list($targets)
	{
		if(!$this->user_id) return FALSE;

		if(!is_array($targets))
		{
			$targets = explode(" ", str_replace(",", " ", $targets));
		}

		foreach($targets as $current_target)
		{
			$current_target = trim($current_target);
			if(!$current_target) continue;

			if($this->check_permission($current_target))
			{
				return TRUE;
			}
		}

		return FALSE;
	}

	public function init()
	{
		add_filter('determine_current_user', array($this, 'set_current_user'), 30);
		add_action('clear_auth_cookie', array($this, 'clear_cookie'));
		add_action('wp_logout', array($this, 'logout'));
		add_action('init', array($this, 'global_block_test'));
		add_action('admin_menu', array($this, 'register_setting_page'));
		add_action('widgets_init', array($this, 'register_widgets'));
		add_action('add_meta_boxes_page', array($this, 'register_meta_box'));
		add_action('save_post', array($this, 'save_page_permissions'));
		add_filter('posts_results', array($this, 'filter_posts'), 10, 2);
		add_filter('wp_nav_menu_objects', array($this, 'filter_menu'));
		add_action('post_edit_form_tag', array($this, 'filter_edit_page'));
	}

	public function set_current_user($a = NULL, $b = NULL, $c = NULL)
	{
		$wanted_user = get_user_by('login', $this->user_id);

		if(!$wanted_user OR !is_a($wanted_user, 'WP_User'))
		{
			$wanted_user = wp_insert_user(array('user_login' => $this->user_id, 'role' => 'editor'));

			if(!$wanted_user OR !is_a($wanted_user, 'WP_User'))
			{
				return FALSE;
			}
		}

		if($wanted_user->ID != $a)
		{
			wp_set_auth_cookie($wanted_user->ID, TRUE, TRUE);
		}

		return $wanted_user->ID;
	}

	public function clear_cookie()
	{
		if(session_id())
		{
			session_write_close();
		}
		session_id($_COOKIE[$this->oc_cookie_name]);
		$old_session_name = session_name($this->oc_cookie_name);
		session_start();
		session_destroy();
		setcookie($this->oc_cookie_name, "", time()-3600);
	}

	public function logout()
	{
		if($this->settings['login_oc_url'])
		{
			header("Location: " . str_replace("%1", home_url(), $this->settings['login_oc_url']));
			wp_die("Logged out from owncloud.", "Logged out", array("response" => 307));
		}
		wp_die("Logged out from owncloud", "Logged out", array("response" => 200));
		return TRUE;
	}

	public function global_block_test()
	{
		if(!$this->user_id AND $this->settings['global_block'])
		{
			if($this->settings['login_oc_url'])
			{
				header("Location: " . str_replace("%1", $_SERVER['REQUEST_URI'], $this->settings['login_oc_url']));
				wp_die("Permission denied, global_block for non owncloud users. " . $this->error, "Permission denied", array("response" => 307));
				die();
			}
			else
			{
				wp_die("Permission denied, global_block for non owncloud users. " . $this->error, "Permission denied", array("response" => 403));
				die();
			}
		}
	}

	public function register_widgets()
	{
		register_widget( 'Owncloud_User_Status_Widget' );
	}

	public function register_meta_box()
	{
		add_meta_box("oc_page_permission", "Owncloud permissions", array($this, "meta_box_page_edit"), 'page', 'side');
	}

	public function register_setting_page()
	{
		add_submenu_page("options-general.php", "Owncloud protection settings", "Owncloud", 'manage_options', "owncloud-prot", array($this, "setting_page"));
	}

	public function meta_box_page_edit($current_post)
	{
		$read_permission = get_post_meta($current_post->ID, '_oc_read_permission', TRUE);
		$edit_permission = get_post_meta($current_post->ID, '_oc_edit_permission', TRUE);

		wp_nonce_field( 'oc_permission', 'oc_permission_nonce' );

		echo "<div>";
		echo '<label for="oc_read_permission">Read permission:</label> ';
		echo '<input type="text" id="oc_read_permission" name="oc_read_permission" value="' . esc_attr( $read_permission ) . '" />';
		echo "</div>";

		echo "<div>";
		echo '<label for="oc_edit_permission">Edit permission:</label> ';
		echo '<input type="text" id="oc_edit_permission" name="oc_edit_permission" value="' . esc_attr( $edit_permission ) . '" />';
		echo "</div>";
	}

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

	public function setting_page()
	{
		echo '<div class="wrap"><div id="icon-tools" class="icon32"></div>';
		echo '<h2>Owncloud protection settings</h2>';
		echo '<form method="post" action="">';
		echo '</div>';

		if(!current_user_can('manage_options'))
		{
			wp_die(__('You do not have sufficient permissions to access this page.'));
		}

		wp_nonce_field( 'owncloud-prot-settings', 'owncloud_prot_settings_nonce' );

		if($_POST['save'])
		{
			if(wp_verify_nonce($_POST['owncloud_prot_settings_nonce'], 'owncloud-prot-settings'))
			{
				update_option("oc_protect_global_block", $_POST["oc_protect_global_block"]);
				update_option("oc_protect_login_url", $_POST["oc_protect_login_url"]);
				update_option("oc_protect_url", $_POST["oc_protect_url"]);

				$this->settings['global_block'] = get_option("oc_protect_global_block", TRUE);
				$this->settings['oc_url'] = get_option("oc_protect_url", "/index.php/apps/files/");
				$this->settings['login_oc_url'] = get_option("oc_protect_login_url", "/");

				echo '<div class="updated"><p><strong>Settings saved</strong></p></div>';
			}
		}

		echo "<div>";
		echo "<label for='oc_protect_global_block' style='width: 100px; display: inline-block;'>Guests</label>";
		echo "<select name='oc_protect_global_block'>";
		echo "<option value='0'" . ($this->settings['global_block'] ? '' : " selected='selected'") . ">Allow guests</option>";
		echo "<option value='1'" . ($this->settings['global_block'] ? " selected='selected'" : '') . ">Only loggedin users</option>";
		echo "</select>";
		echo "</div>";

		echo "<div>";
		echo "<label for='oc_protect_login_url' style='width: 100px; display: inline-block;'>Login url</label>";
		echo "<input name='oc_protect_login_url' value='{$this->settings['login_oc_url']}' />";
		echo "</div>";

		echo "<div>";
		echo "<label for='oc_protect_url' style='width: 100px; display: inline-block;'>App url</label>";
		echo "<input name='oc_protect_url' value='{$this->settings['oc_url']}' />";
		echo "</div>";

		echo "<input type='submit' name='save' class='button-primary' value='Save' />";
		echo "</form>";
		echo "</div>";
	}

	public function filter_posts($posts, $query_object)
	{
// 		if(!$this->admin)
		if($this->user_id != 'root')
		{
			foreach($posts as $index => $current_post)
			{
				if($current_post->post_type == 'page')
				{
					$read_permission = get_post_meta($current_post->ID, '_oc_read_permission', TRUE);
					if($read_permission)
					{
						if(!$this->check_permission_list($read_permission))
						{
							unset($posts[$index]);
						}
					}
				}
			}
		}

		return $posts;
	}

	public function filter_menu($menu)
	{
// 		if(!$this->admin)
		if($this->user_id != 'root')
		{
			foreach($menu as $index => $current_menu)
			{
				if($current_menu->object == 'page')
				{

					$read_permission = get_post_meta($current_menu->object_id, '_oc_read_permission', TRUE);
					if($read_permission)
					{
						if(!$this->check_permission_list($read_permission))
						{
							unset($menu[$index]);
						}
					}
				}
			}
		}

		return $menu;
	}

	public function filter_edit_page($current_post)
	{
// 		if($this->admin)
		if($this->user_id == 'root') return TRUE;
		if($current_post->post_type != 'page') return TRUE;
		$edit_permission = get_post_meta($current_post->ID, '_oc_edit_permission', TRUE);
		if(!$edit_permission) $edit_permission = get_post_meta($current_post->ID, '_oc_read_permission', TRUE);
		if(!$edit_permission) return TRUE;
		if($this->check_permission_list($edit_permission)) return TRUE;
		wp_die("Permission denied, you not allowed to edit this page.", "Permission denied", array("response" => 403));
	}
}

class Owncloud_User_Status_Widget extends WP_Widget
{
	public function __construct()
	{
		parent::__construct(
			'owncloud_user_status_widget', // Base ID
			'Owncloud user status', // Name
			array('description' => 'Show status for loged in owncloud user', ) // Args
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

		echo "{$widget_args['before_title']}Owncloud user{$widget_args['after_title']}";

		if($GLOBALS['oc_protect']->user_id)
		{
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

			if($show_link AND $GLOBALS['oc_protect']->settings['oc_url'])
			{
				echo "<p><a href='{$GLOBALS['oc_protect']->settings['oc_url']}'>Show filelist</a></p>";
			}
		}
		else
		{
			echo "<p>Not logged in</p>";

			if($GLOBALS['oc_protect']->settings['oc_url'])
			{
				echo "<p><a href='{$GLOBALS['oc_protect']->settings['oc_url']}'>Login</a></p>";
			}
		}

		/// DEBUG
		if(TRUE)
		{
			if(isset($GLOBALS['post']) AND $GLOBALS['post']->post_type == 'page')
			{
				echo "<p>Page: {$GLOBALS['post']->ID}</p>";

				$permission_html['read'] = array();
				$permission_html['edit'] = array();
				$permission['read'] = get_post_meta($GLOBALS['post']->ID, '_oc_read_permission', TRUE);
				$permission['edit'] = get_post_meta($GLOBALS['post']->ID, '_oc_edit_permission', TRUE);

				foreach(array('read', 'edit') as $ptype)
				{
					foreach(explode(" ", str_replace(",", " ", $permission[$ptype])) as $current_target)
					{
						$current_target = trim($current_target);
						if(!$current_target) continue;

						if($GLOBALS['oc_protect']->check_permission($current_target))
						{
							$permission_html[$ptype][] = "<b>" . $current_target . "</b>";
						}
						else
						{
							$permission_html[$ptype][] = "<span>" . $current_target . "</span>";
						}
					}
				}

				echo "<p>Read: " . implode(", ", $permission_html['read']) . "</p>";
				echo "<p>Edit: " . implode(", ", $permission_html['edit']) . "</p>";

			}
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

	if(!ob_get_level()) ob_start();

	$GLOBALS['oc_protect'] = new oc_protect();
	$GLOBALS['oc_protect']->init();
