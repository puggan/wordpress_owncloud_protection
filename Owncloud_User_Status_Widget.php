<?php

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
			_x('Owncloud user status', 'widget name', 'owncloud_protection'), // Name
			array('description' => __('Show status for loged in owncloud user', 'owncloud_protection'), ) // Args
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
				echo "<p>" . _x('User', 'label', 'owncloud_protection') . ": {$GLOBALS['oc_protect']->user_id}</p>";
			}

			// check option for show_groups
			if(isset($instance['show_groups']) AND $instance['show_groups'])
			{
				// and owncloud user is a member of at least one group
				if($GLOBALS['oc_protect']->groups)
				{
					// show groups
					echo "<p>" . _x('Groups', 'label', 'owncloud_protection') . ": " . implode(", ", $GLOBALS['oc_protect']->groups) . "</p>";
				}
				else
				{
					// show error, use italic, to make it more noticable that its not a group named none
					echo "<p>" . _x('Groups', 'label', 'owncloud_protection') . ": <i>" . _x('(none)', 'group count', 'owncloud_protection') . "</i></p>";
				}
			}

			// check option for show_link, and if we have a posible url to show
			if(isset($instance['show_link']) AND $instance['show_link'] AND $GLOBALS['oc_protect']->settings['oc_url'])
			{
				// show link
				echo "<p><a href='{$GLOBALS['oc_protect']->settings['oc_url']}'>" . _x('Show filelist', 'link', 'owncloud_protection') . "</a></p>";
			}
		}
		// if we aren't logged in
		else
		{
			// write error insted of user
			echo "<p>" . _x('Not logged in', 'error', 'owncloud_protection') . "</p>";

			// if we have a url to loginpage
			if($GLOBALS['oc_protect']->settings['login_oc_url'])
			{
				// add a reference back to current page to login url
				$login_url = str_replace("%1", $_SERVER['REQUEST_URI'], $GLOBALS['oc_protect']->settings['login_oc_url']);

				// write link to login url
				echo "<p><a href='{$login_url}'>" . _x('Login', 'link', 'owncloud_protection') . "</a></p>";
			}
		}

		// if option for debug information is turned on (off by default)
		if(isset($instance['show_debug']) AND $instance['show_debug'])
		{
			// and we visiting a page at the momment
			if(isset($GLOBALS['post']) AND $GLOBALS['post']->post_type == 'page')
			{
				// tell user what page we are on, using ID
				echo "<p>" . _x('Page', 'label', 'owncloud_protection') . ": {$GLOBALS['post']->ID}</p>";

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
				echo "<p>" . _x('Read', 'label permissionlist', 'owncloud_protection') . ": " . implode(", ", $permission_html['read']) . "</p>";
				echo "<p>" . _x('Edit', 'label permissionlist', 'owncloud_protection') . ": " . implode(", ", $permission_html['edit']) . "</p>";
			}

			// if error has occured
			if($GLOBALS['oc_protect']->error)
			{
				// dispaly last error
				echo "<p>" . _x('Error', 'label', 'owncloud_protection') . ": {$GLOBALS['oc_protect']->error}</p>";
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
		$fields['username']['title'] = _x('Show username', 'label setting', 'owncloud_protection');
		$fields['username']['value'] = (isset($instance['show_username']) ? $instance['show_username'] : TRUE);

		// define filed show_groups
		$fields['groups']['id'] = $this->get_field_id('show_groups');
		$fields['groups']['name'] = $this->get_field_name( 'show_groups' );
		$fields['groups']['title'] = _x('Show groups', 'label setting', 'owncloud_protection');
		$fields['groups']['value'] = (isset($instance['show_groups']) ? $instance['show_groups'] : TRUE);

		// define filed show_link
		$fields['link']['id'] = $this->get_field_id('show_link');
		$fields['link']['name'] = $this->get_field_name( 'show_link' );
		$fields['link']['title'] = _x('Show link', 'label setting', 'owncloud_protection');
		$fields['link']['value'] = (isset($instance['show_link']) ? $instance['show_link'] : TRUE);

		// define filed show_debug
		$fields['debug']['id'] = $this->get_field_id('show_debug');
		$fields['debug']['name'] = $this->get_field_name( 'show_debug' );
		$fields['debug']['title'] = _x('Debug info', 'label setting', 'owncloud_protection');
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
