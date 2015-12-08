# Postfixadmin Password functions

This repository is created to handle the password encryption present in Postfix Admin, in other PHP projects.

For example if you need to update the ```mailbox.password``` field of your current postfixadmin installation.



Compatibility
-------------

This library is compatible with Postfix Admin 2.3.4


Install
-------

Example for your `composer.json` file:

```
{
    "minimum-stability": "dev",
    "repositories": [
      {
        "type": "vcs",
        "url": "https://github.com/CELESTE77/postfixadmin-password"
      }
    ],
    "require": {
        "CELESTE77/postfixadmin-password": "master"
    }
}
```



Usage
-----

```php
// Include the library
require_once "vendor/CELESTE77/postfixadmin-password/postfixadmin-password.php";

// Override the $CONF parameters with the paramaters used
// in YOUR current installation of Postfix Admin in postfixadmin/config.inc.php file
$CONF['encrypt'] = 'md5scrypt'; // default is md5crypt
$CONF['database_host'] = 'localhost';
$CONF['database_user'] = 'postfix';
$CONF['database_password'] = 'postfix';
$CONF['database_name'] = 'postfix';
$CONF['database_prefix'] = 'postfix_';

// Call the pacrypt() function.
$password = pacrypt('helloworld');
```
