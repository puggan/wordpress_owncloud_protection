# Wordpress OwnCloud protection v1.0.0
Wordpress pluing for protection pages using ownclouds users and groups

# Requirment
* wordpress and owncloud
* the wordpress need to be able to read ownclouds cookies, so put both on the same domian
* the wordpress need to be able to share session, so use same session-handerl and session.save_path
* the plugin need to look up grous in database, so at them moment the need to share database
* use the same name for owncloud user and wordpress user. (i like to call the admins in both for 'root')

# Install
* Install Owncloud at your webserver (Devloped using OwnCloud v7.0.4)
* Install Wordpress at the same domain (in a subfolder of your Owncloud installation) (Devloped using Wordpress v4.1.0)
* add the folder owncloud_protection to wordpress plugin directory 'wp-content/plugins/'
* visit wordpress pluginpage in adminpanel 'wp-admin/plugins.php'
* activate Owncloud Protection
* visit the wordpress owncloud settings page 'wp-admin/options-general.php?page=owncloud-prot'
* update urls and save, the default url works if your owncloud is installed in the domains documentroot.
* logout of wordpress
* try the synced authentication by loggin in in owncloud, and then visit the wordpress site
* optional: turn off guest access in wordpress owncloud settings page.
* optional: set the owncloud default app to wordpress
  * database table: oc_appconfig
  * appid: core
  * configkey: defaultpage
  * `INSERT INTO oc_appconfig SET appid = 'core', configkey = 'defaultpage', configvalue = 'wp/' ON DUPLICATE KEY UPDATE configvalue = 'wp/';`
