<?php
/** 
 * Postfix Admin 
 * 
 * LICENSE 
 * This source file is subject to the GPL license that is bundled with  
 * this package in the file LICENSE.TXT. 
 * 
 * Further details on the project are available at : 
 *     http://www.postfixadmin.com or http://postfixadmin.sf.net 
 * 
 * @version $Id: functions.inc.php 1180 2011-09-16 18:41:00Z christian_boltz $ 
 * @license GNU GPL v2 or later. 
 * 
 * File: functions.inc.php
 * Contains re-usable code.
 */

$version = '2.3.4';


/**
 * Clean a string, escaping any meta characters that could be
 * used to disrupt an SQL string. i.e. "'" => "\'" etc.
 *
 * @param String (or Array) 
 * @return String (or Array) of cleaned data, suitable for use within an SQL
 *    statement.
 */
function escape_string ($string)
{
    global $CONF;
    // if the string is actually an array, do a recursive cleaning.
    // Note, the array keys are not cleaned.
    if(is_array($string)) {
        $clean = array();
        foreach(array_keys($string) as $row) {
            $clean[$row] = escape_string($string[$row]);  
        }
        return $clean;
    }
    if (get_magic_quotes_gpc ())
    {
        $string = stripslashes($string);
    }
    if (!is_numeric($string))
    {
        $link = db_connect();
        if ($CONF['database_type'] == "mysql")
        {
            $escaped_string = mysql_real_escape_string($string, $link);
        }
        if ($CONF['database_type'] == "mysqli")
        {
            $escaped_string = mysqli_real_escape_string($link, $string);
        }
        if ($CONF['database_type'] == "pgsql") 
        {
            // php 5.2+ allows for $link to be specified.
            if (version_compare(phpversion(), "5.2.0", ">="))
            {
                $escaped_string = pg_escape_string($link, $string);
            }
            else 
            {
                $escaped_string = pg_escape_string($string);
            }
        }
    }
    else
    {
        $escaped_string = $string;
    }
    return $escaped_string;
}






/**
 * Encrypt a password, using the apparopriate hashing mechanism as defined in 
 * config.inc.php ($CONF['encrypt']). 
 * When wanting to compare one pw to another, it's necessary to provide the salt used - hence
 * the second parameter ($pw_db), which is the existing hash from the DB.
 *
 * @param string $pw
 * @param string $encrypted password
 * @return string encrypted password.
 */
function pacrypt ($pw, $pw_db="")
{
    global $CONF;
    $pw = stripslashes($pw);
    $password = "";
    $salt = "";

    if ($CONF['encrypt'] == 'md5crypt') {
        $split_salt = preg_split ('/\$/', $pw_db);
        if (isset ($split_salt[2])) {
            $salt = $split_salt[2];
        }
        $password = md5crypt ($pw, $salt);
    }

    elseif ($CONF['encrypt'] == 'md5') {
        $password = md5($pw);
    }

    elseif ($CONF['encrypt'] == 'system') {
        if (preg_match("/\\$1\\$/", $pw_db)) {
            $split_salt = preg_split ('/\$/', $pw_db);
            $salt = "\$1\$${split_salt[2]}\$";
        }
        else {
            if (strlen($pw_db) == 0) {
                $salt = substr (md5 (mt_rand ()), 0, 2);
            }
            else {
                $salt = substr ($pw_db, 0, 2);
            }
        }
        $password = crypt ($pw, $salt);
    }

    elseif ($CONF['encrypt'] == 'cleartext') {
        $password = $pw;
    }

    // See https://sourceforge.net/tracker/?func=detail&atid=937966&aid=1793352&group_id=191583
    // this is apparently useful for pam_mysql etc.
    elseif ($CONF['encrypt'] == 'mysql_encrypt')
    {
        if ($pw_db!="") {
            $salt=substr($pw_db,0,2);
            $res=db_query("SELECT ENCRYPT('".$pw."','".$salt."');");
        } else {
            $res=db_query("SELECT ENCRYPT('".$pw."');");
        }
        $l = db_row($res["result"]);
        $password = $l[0];
    }

    elseif ($CONF['encrypt'] == 'authlib') {
        $flavor = $CONF['authlib_default_flavor'];
        $salt = substr(create_salt(), 0, 2); # courier-authlib supports only two-character salts
        if(preg_match('/^{.*}/', $pw_db)) {
            // we have a flavor in the db -> use it instead of default flavor
            $result = preg_split('/[{}]/', $pw_db, 3); # split at { and/or }
            $flavor = $result[1];  
            $salt = substr($result[2], 0, 2);
        }

        if(stripos($flavor, 'md5raw') === 0) {
            $password = '{' . $flavor . '}' . md5($pw);
        } elseif(stripos($flavor, 'md5') === 0) {
            $password = '{' . $flavor . '}' . base64_encode(md5($pw, TRUE));
        } elseif(stripos($flavor, 'crypt') === 0) {
            $password = '{' . $flavor . '}' . crypt($pw, $salt);
	} elseif(stripos($flavor, 'SHA') === 0) {
	    $password = '{' . $flavor . '}' . base64_encode(sha1($pw, TRUE));
        } else {
            die("authlib_default_flavor '" . $flavor . "' unknown. Valid flavors are 'md5raw', 'md5', 'SHA' and 'crypt'");
        }
    }

    elseif (preg_match("/^dovecot:/", $CONF['encrypt'])) {
        $split_method = preg_split ('/:/', $CONF['encrypt']);
        $method       = strtoupper($split_method[1]);
        if (! preg_match("/^[A-Z0-9-]+$/", $method)) { die("invalid dovecot encryption method"); }  # TODO: check against a fixed list?
        if (strtolower($method) == 'md5-crypt') die("\$CONF['encrypt'] = 'dovecot:md5-crypt' will not work because dovecotpw generates a random salt each time. Please use \$CONF['encrypt'] = 'md5crypt' instead."); 

        $dovecotpw = "dovecotpw";
        if (!empty($CONF['dovecotpw'])) $dovecotpw = $CONF['dovecotpw'];

        # Use proc_open call to avoid safe_mode problems and to prevent showing plain password in process table
        $spec = array(
            0 => array("pipe", "r"), // stdin
            1 => array("pipe", "w"), // stdout
            2 => array("pipe", "w"), // stderr
        );

        $pipe = proc_open("$dovecotpw '-s' $method", $spec, $pipes);

        if (!$pipe) {
            die("can't proc_open $dovecotpw");
        } else {
            // use dovecot's stdin, it uses getpass() twice
            // Write pass in pipe stdin
            fwrite($pipes[0], $pw . "\n", 1+strlen($pw)); usleep(1000);
            fwrite($pipes[0], $pw . "\n", 1+strlen($pw));
            fclose($pipes[0]);

            // Read hash from pipe stdout
            $password = fread($pipes[1], "200");

            if ( !preg_match('/^\{' . $method . '\}/', $password)) {
                $stderr_output = stream_get_contents($pipes[2]);
                error_log('dovecotpw password encryption failed.');
                error_log('STDERR output: ' . $stderr_output);
                die("can't encrypt password with dovecotpw, see error log for details"); 
            }

            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($pipe);

            $password = trim(str_replace('{' . $method . '}', '', $password));
        }
    }

    else {
        die ('unknown/invalid $CONF["encrypt"] setting: ' . $CONF['encrypt']);
    }

    $password = escape_string ($password);
    return $password;
}

//
// md5crypt
// Action: Creates MD5 encrypted password
// Call: md5crypt (string cleartextpassword)
//

function md5crypt ($pw, $salt="", $magic="")
{
    $MAGIC = "$1$";

    if ($magic == "") $magic = $MAGIC;
    if ($salt == "") $salt = create_salt ();
    $slist = explode ("$", $salt);
    if ($slist[0] == "1") $salt = $slist[1];

    $salt = substr ($salt, 0, 8);
    $ctx = $pw . $magic . $salt;
    $final = hex2bin (md5 ($pw . $salt . $pw));

    for ($i=strlen ($pw); $i>0; $i-=16)
    {
        if ($i > 16)
        {
            $ctx .= substr ($final,0,16);
        }
        else
        {
            $ctx .= substr ($final,0,$i);
        }
    }
    $i = strlen ($pw);

    while ($i > 0)
    {
        if ($i & 1) $ctx .= chr (0);
        else $ctx .= $pw[0];
        $i = $i >> 1;
    }
    $final = hex2bin (md5 ($ctx));

    for ($i=0;$i<1000;$i++)
    {
        $ctx1 = "";
        if ($i & 1)
        {
            $ctx1 .= $pw;
        }
        else
        {
            $ctx1 .= substr ($final,0,16);
        }
        if ($i % 3) $ctx1 .= $salt;
        if ($i % 7) $ctx1 .= $pw;
        if ($i & 1)
        {
            $ctx1 .= substr ($final,0,16);
        }
        else
        {
            $ctx1 .= $pw;
        }
        $final = hex2bin (md5 ($ctx1));
    }
    $passwd = "";
    $passwd .= to64 (((ord ($final[0]) << 16) | (ord ($final[6]) << 8) | (ord ($final[12]))), 4);
    $passwd .= to64 (((ord ($final[1]) << 16) | (ord ($final[7]) << 8) | (ord ($final[13]))), 4);
    $passwd .= to64 (((ord ($final[2]) << 16) | (ord ($final[8]) << 8) | (ord ($final[14]))), 4);
    $passwd .= to64 (((ord ($final[3]) << 16) | (ord ($final[9]) << 8) | (ord ($final[15]))), 4);
    $passwd .= to64 (((ord ($final[4]) << 16) | (ord ($final[10]) << 8) | (ord ($final[5]))), 4);
    $passwd .= to64 (ord ($final[11]), 2);
    return "$magic$salt\$$passwd";
}

function create_salt ()
{
    srand ((double) microtime ()*1000000);
    $salt = substr (md5 (rand (0,9999999)), 0, 8);
    return $salt;
}

// Modification PHP-FPM
function hex2bin_apport ($str)
{
    $len = strlen ($str);
    $nstr = "";
    for ($i=0;$i<$len;$i+=2)
    {
        $num = sscanf (substr ($str,$i,2), "%x");
        $nstr.=chr ($num[0]);
    }
    return $nstr;
}

function to64 ($v, $n)
{
    $ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    $ret = "";
    while (($n - 1) >= 0)
    {
        $n--;
        $ret .= $ITOA64[$v & 0x3f];
        $v = $v >> 6;
    }
    return $ret;
}





/**
 * db_connect
 * Action: Makes a connection to the database if it doesn't exist
 * Call: db_connect ()
 * Optional parameter: $ignore_errors = TRUE, used by setup.php
 *
 * Return value:
 * a) without $ignore_errors or $ignore_errors == 0
 *    - $link - the database connection -OR-
 *    - call die() in case of connection problems
 * b) with $ignore_errors == TRUE
 *    array($link, $error_text);
 */
function db_connect ($ignore_errors = 0)
{
    global $CONF;
    global $DEBUG_TEXT;
    if ($ignore_errors != 0) $DEBUG_TEXT = '';
    $error_text = '';
    $link = 0;

    if ($CONF['database_type'] == "mysql")
    {
        if (function_exists ("mysql_connect"))
        {
            $link = @mysql_connect ($CONF['database_host'], $CONF['database_user'], $CONF['database_password']) or $error_text .= ("<p />DEBUG INFORMATION:<br />Connect: " .  mysql_error () . "$DEBUG_TEXT");
            if ($link) {
                @mysql_query("SET CHARACTER SET utf8",$link);
                @mysql_query("SET COLLATION_CONNECTION='utf8_general_ci'",$link);
                $succes = @mysql_select_db ($CONF['database_name'], $link) or $error_text .= ("<p />DEBUG INFORMATION:<br />MySQL Select Database: " .  mysql_error () . "$DEBUG_TEXT");
            }
        }
        else
        {
            $error_text .= "<p />DEBUG INFORMATION:<br />MySQL 3.x / 4.0 functions not available! (php5-mysql installed?)<br />database_type = 'mysql' in config.inc.php, are you using a different database? $DEBUG_TEXT";
        }
    }
    elseif ($CONF['database_type'] == "mysqli")
    {
        if (function_exists ("mysqli_connect"))
        {
            $link = @mysqli_connect ($CONF['database_host'], $CONF['database_user'], $CONF['database_password']) or $error_text .= ("<p />DEBUG INFORMATION:<br />Connect: " .  mysqli_connect_error () . "$DEBUG_TEXT");
            if ($link) {
                @mysqli_query($link,"SET CHARACTER SET utf8");
                @mysqli_query($link,"SET COLLATION_CONNECTION='utf8_general_ci'");
                $success = @mysqli_select_db ($link, $CONF['database_name']) or $error_text .= ("<p />DEBUG INFORMATION:<br />MySQLi Select Database: " .  mysqli_error ($link) . "$DEBUG_TEXT");
            }
        }
        else
        {
            $error_text .= "<p />DEBUG INFORMATION:<br />MySQL 4.1 functions not available! (php5-mysqli installed?)<br />database_type = 'mysqli' in config.inc.php, are you using a different database? $DEBUG_TEXT";
        }
    }
    elseif ($CONF['database_type'] == "pgsql")
    {
        if (function_exists ("pg_pconnect"))
        {
            if(!isset($CONF['database_port'])) {
                $CONF['database_port'] = '5432';
            }
            $connect_string = "host=" . $CONF['database_host'] . " port=" . $CONF['database_port'] . " dbname=" . $CONF['database_name'] . " user=" . $CONF['database_user'] . " password=" . $CONF['database_password'];
            $link = @pg_pconnect ($connect_string) or $error_text .= ("<p />DEBUG INFORMATION:<br />Connect: failed to connect to database. $DEBUG_TEXT");
            if ($link) pg_set_client_encoding($link, 'UNICODE');
        }
        else
        {
            $error_text .= "<p />DEBUG INFORMATION:<br />PostgreSQL functions not available! (php5-pgsql installed?)<br />database_type = 'pgsql' in config.inc.php, are you using a different database? $DEBUG_TEXT";
        }
    }
    else
    {
        $error_text = "<p />DEBUG INFORMATION:<br />Invalid \$CONF['database_type']! Please fix your config.inc.php! $DEBUG_TEXT";
    }

    if ($ignore_errors)
    {
        return array($link, $error_text);
    }
    elseif ($error_text != "")
    {
        print $error_text;
        die();
    }
    elseif ($link)
    {
        return $link;
    }
    else
    {
        print "DEBUG INFORMATION:<br />\n";
        print "Connect: Unable to connect to database<br />\n";
        print "<br />\n";
        print "Make sure that you have set the correct database type in the config.inc.php file<br />\n";
        print $DEBUG_TEXT;
        die();
    }
}

/**
 * Returns the appropriate boolean value for the database.
 * Currently only PostgreSQL and MySQL are supported.
 * @param boolean $bool (REQUIRED)
 * @return String or int as appropriate.
 */
function db_get_boolean($bool) {
    if(!is_bool($bool)) {
        die("Invalid usage of 'db_get_boolean($bool)'");
    }

    global $CONF;
    if($CONF['database_type']=='pgsql') {
        // return either true or false (unquoted strings)
        if($bool) {
            return 't';
        }  
        return 'f';
    }
    elseif($CONF['database_type'] == 'mysql' || $CONF['database_type'] == 'mysqli') {
        if($bool) {
            return 1;  
        } 
        return 0;
    }
}

//
// db_query
// Action: Sends a query to the database and returns query result and number of rows
// Call: db_query (string query)
// Optional parameter: $ignore_errors = TRUE, used by upgrade.php
//
function db_query ($query, $ignore_errors = 0)
{
    global $CONF;
    global $DEBUG_TEXT;
    $result = "";
    $number_rows = "";
    static $link;
    $error_text = "";
    if ($ignore_errors) $DEBUG_TEXT = "";

    if (!is_resource($link)) $link = db_connect ();

    if ($CONF['database_type'] == "mysql") $result = @mysql_query ($query, $link) 
        or $error_text = "<p />DEBUG INFORMATION:<br />Invalid query: " . mysql_error($link) . "$DEBUG_TEXT";
    if ($CONF['database_type'] == "mysqli") $result = @mysqli_query ($link, $query) 
        or $error_text = "<p />DEBUG INFORMATION:<br />Invalid query: " . mysqli_error($link) . "$DEBUG_TEXT";
    if ($CONF['database_type'] == "pgsql")
    {
        $result = @pg_query ($link, $query) 
            or $error_text = "<p />DEBUG INFORMATION:<br />Invalid query: " . pg_last_error() . "$DEBUG_TEXT";
    }
    if ($error_text != "" && $ignore_errors == 0) die($error_text);

    if ($error_text == "") {
        if (preg_match("/^SELECT/i", trim($query)))
        {
            // if $query was a SELECT statement check the number of rows with [database_type]_num_rows ().
            if ($CONF['database_type'] == "mysql") $number_rows = mysql_num_rows ($result);
            if ($CONF['database_type'] == "mysqli") $number_rows = mysqli_num_rows ($result);
            if ($CONF['database_type'] == "pgsql") $number_rows = pg_num_rows ($result);
        }
        else
        {
            // if $query was something else, UPDATE, DELETE or INSERT check the number of rows with
            // [database_type]_affected_rows ().
            if ($CONF['database_type'] == "mysql") $number_rows = mysql_affected_rows ($link);
            if ($CONF['database_type'] == "mysqli") $number_rows = mysqli_affected_rows ($link);
            if ($CONF['database_type'] == "pgsql") $number_rows = pg_affected_rows ($result);
        }
    }

    $return = array (
        "result" => $result,
        "rows" => $number_rows,
        "error" => $error_text
    );
    return $return;
}



// db_row
// Action: Returns a row from a table
// Call: db_row (int result)
//
function db_row ($result)
{
    global $CONF;
    $row = "";
    if ($CONF['database_type'] == "mysql") $row = mysql_fetch_row ($result);
    if ($CONF['database_type'] == "mysqli") $row = mysqli_fetch_row ($result);
    if ($CONF['database_type'] == "pgsql") $row = pg_fetch_row ($result);
    return $row;
}



// db_array
// Action: Returns a row from a table
// Call: db_array (int result)
//
function db_array ($result)
{
    global $CONF;
    $row = "";
    if ($CONF['database_type'] == "mysql") $row = mysql_fetch_array ($result);
    if ($CONF['database_type'] == "mysqli") $row = mysqli_fetch_array ($result);
    if ($CONF['database_type'] == "pgsql") $row = pg_fetch_array ($result);
    return $row;
}



// db_assoc
// Action: Returns a row from a table
// Call: db_assoc(int result)
//
function db_assoc ($result)
{
    global $CONF;
    $row = "";
    if ($CONF['database_type'] == "mysql") $row = mysql_fetch_assoc ($result);
    if ($CONF['database_type'] == "mysqli") $row = mysqli_fetch_assoc ($result);
    if ($CONF['database_type'] == "pgsql") $row = pg_fetch_assoc ($result);
    return $row;
}



//
// db_delete
// Action: Deletes a row from a specified table
// Call: db_delete (string table, string where, string delete)
//
function db_delete ($table,$where,$delete)
{
    # $table = table_by_key($table); # intentionally disabled to avoid breaking delete.php in 2.3.x
    # This makes the behaviour of this function incorrect, but delete.php is the only file in 2.3.x calling db_delete and expects this (wrong) behaviour.
    $query = "DELETE FROM $table WHERE " . escape_string($where) . "='" . escape_string($delete) . "'";
    $result = db_query ($query);
    if ($result['rows'] >= 1)
    {
        return $result['rows'];
    }
    else
    {
        return true;
    }
}


/**
 * db_insert
 * Action: Inserts a row from a specified table
 * Call: db_insert (string table, array values)
 * @param String $table - table name
 * @param array - key/value map of data to insert into the table.
 * @param array (optional) - array of fields to set to now()
 * @return int - number of inserted rows
 */
function db_insert ($table, $values, $timestamp = array())
{
    $table = table_by_key ($table);

    foreach(array_keys($values) as $key) {
        $values[$key] = "'" . escape_string($values[$key]) . "'";
    }

    foreach($timestamp as $key) {
        $values[$key] = "now()";
    }

    $sql_values = "(" . implode(",",escape_string(array_keys($values))).") VALUES (".implode(",",$values).")";

    $result = db_query ("INSERT INTO $table $sql_values");
    return $result['rows'];
}


/**
 * db_update
 * Action: Updates a specified table
 * Call: db_update (string table, array values, string where)
 * @param String $table - table name
 * @param String - WHERE condition
 * @param array - key/value map of data to insert into the table.
 * @param array (optional) - array of fields to set to now()
 * @return int - number of updated rows
 */
function db_update ($table, $where, $values, $timestamp = array())
{
    $table = table_by_key ($table);

    foreach(array_keys($values) as $key) {
        $sql_values[$key] = escape_string($key) . "='" . escape_string($values[$key]) . "'";
    }

    foreach($timestamp as $key) {
        $sql_values[$key] = escape_string($key) . "=now()";
    }

    $sql="UPDATE $table SET ".implode(",",$sql_values)." WHERE $where";

    $result = db_query ($sql);
    return $result['rows'];
}



/**
 * db_log
 * Action: Logs actions from admin
 * Call: db_log (string username, string domain, string action, string data)
 * Possible actions are:
 * 'create_alias'
 * 'create_alias_domain'
 * 'create_mailbox'
 * 'delete_alias'
 * 'delete_alias_domain'
 * 'delete_mailbox'
 * 'edit_alias'
 * 'edit_alias_state'
 * 'edit_alias_domain_state'
 * 'edit_mailbox'
 * 'edit_mailbox_state'
 * 'edit_password'
 */
function db_log ($username,$domain,$action,$data)
{
    global $CONF;
    global $table_log;
    $REMOTE_ADDR = $_SERVER['REMOTE_ADDR'];

    $action_list = array('create_alias', 'create_alias_domain', 'delete_alias', 'delete_alias_domain', 'edit_alias', 'create_mailbox', 'delete_mailbox', 'edit_mailbox', 'edit_alias_state', 'edit_alias_domain_state', 'edit_mailbox_state', 'edit_password');

    if(!in_array($action, $action_list)) {
        die("Invalid log action : $action");   // could do with something better?
    }

    if ($CONF['logging'] == 'YES')
    {
        $logdata = array(
            'username'  => "$username ($REMOTE_ADDR)",
            'domain'    => $domain,
            'action'    => $action,
            'data'      => $data,
        );
        $result = db_insert('log', $logdata, array('timestamp') );
        #$result = db_query ("INSERT INTO $table_log (timestamp,username,domain,action,data) VALUES (NOW(),'$username ($REMOTE_ADDR)','$domain','$action','$data')");
        if ($result != 1)
        {
            return false;
        }
        else
        {
            return true;
        }
    }
}

/**
 * db_in_clause
 * Action: builds and returns the "field in(x, y)" clause for database queries
 * Call: db_in_clause (string field, array values)
 */
function db_in_clause($field, $values) {
    return " $field IN ('"
    . implode("','",escape_string(array_values($values))) 
    . "') "; 
}

//
// table_by_key
// Action: Return table name for given key
// Call: table_by_key (string table_key)
//
function table_by_key ($table_key)
{
    global $CONF;
    $table = $CONF['database_prefix'].$CONF['database_tables'][$table_key];
    if (empty($table)) $table = $table_key;
    return $table;
}



$table_admin = table_by_key ('admin');
$table_alias = table_by_key ('alias');
$table_alias_domain = table_by_key ('alias_domain');
$table_domain = table_by_key ('domain');
$table_domain_admins = table_by_key ('domain_admins');
$table_log = table_by_key ('log');
$table_mailbox = table_by_key ('mailbox');
$table_vacation = table_by_key ('vacation');
$table_vacation_notification = table_by_key('vacation_notification');
$table_quota = table_by_key ('quota');
$table_quota2 = table_by_key ('quota2');
/* vim: set expandtab softtabstop=4 tabstop=4 shiftwidth=4: */
