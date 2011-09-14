<?php

/*

    pcrypt - Javascript encryption for privacy and security in cloud computing
    Copyright (C) 2010 Benny Nissen.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/


// Place this file in a location not accessible to the public web-server (security issue)


include($folder."pcrypt.inc.php");
require_once $folder."adodb_lite/adodb.inc.php";
include_once($folder."phpmailer/class.phpmailer.php");
require_once("json.inc.php");

//http://forums.contribs.org/index.php?topic=29433.0

function mailoutput($to, $mailbody)
{
	$mail = new PHPMailer();
	$mail->IsMail();
	$mail->SetLanguage("en");
	$mail->IsHTML(true);
	$mail->FromName = "noreply@pcrypt.org"; 
	$mail->From = $mail->FromName;
	$mail->Subject = "Password Crypt cron log";
	$mail->WordWrap = 50;

	$mail->MsgHTML($mailbody);
	$mail->AltBody = strip_tags(preg_replace("/<br>/", "\r\n", $mailbody));
	$mail->AddAddress($to);
	if(!$mail->Send()) 
	{
		die("Mail Error: " . $mail->ErrorInfo);
	}	
}

// Check MD5 hash for all files
function MD5readfolder($dir, $excludearray, &$array)
{
	if($str[strlen($str)-1] != '/')
		$str[strlen($str)] = '/';	

	if (is_dir($dir)) 
	{
		if ($dh = opendir($dir)) 
		{
			while (($file = readdir($dh)) !== false) 
			{
				if(($file[0] != ".") && (!in_array($dir.$file, $excludearray)))				
				if(is_dir($dir.$file))
				{					
					MD5readfolder($dir.$file."/", $excludearray, $array);
				}
				else
				{
					$ext = substr(strrchr($dir.$file, '.'), 1);

					if(!strcasecmp($ext, "php") || !strcasecmp($ext, "js") || !strcasecmp($ext, "htm") || !strcasecmp($ext, "html") || !strcasecmp($ext, "css"))
						$array[$dir.$file] = md5_file($dir.$file); //$array[basename($dir)."/".$file] = md5_file($dir.$file);
				}
			}
			closedir($dh);
		}
	}
}

$db = ADONewConnection($db_system);
$result = $db->Connect($db_server, $db_user, $db_password, $db_database) or die(PC_ERRORDBCONNECT);

$mailbody = "<br>Password Crypt cron log<br>";

// Total number of users
$query = "SELECT COUNT(*) AS number FROM `users`";
$result = $db->Execute($query) or die("Error in sql: $query. " . $db->ErrorMsg());

$mailbody .= "<br>Users: ".$result->fields['number'];

// get number of users that have been on the system for the last 24 hours 
$query = "SELECT COUNT(*) AS number FROM `users` WHERE (`lastlogin` > (NOW() - INTERVAL 1 DAY))";
$result = $db->Execute($query) or die("Error in sql: $query. " . $db->ErrorMsg());

$mailbody .= "<br>Active users: ".$result->fields['number'];

// get number of users that has not used the system for the last 2 years 
$query = "SELECT COUNT(*) AS number FROM `users` WHERE (`lastlogin` < (NOW() - INTERVAL 2 YEAR))";
$result = $db->Execute($query) or die("Error in sql: $query. " . $db->ErrorMsg());

$mailbody .= "<br>Inactive users: ".$result->fields['number'];

// delete old data from session database 
$query = "DELETE FROM `sessions` WHERE `updated` < (NOW() - INTERVAL 1 DAY)"; 
$result = $db->Execute($query) or die("Error in sql: $query. " . $db->ErrorMsg());

$mailbody .= "<br>Sessions deleted: ".$db->Affected_Rows();

// delete old data from bruteforce database (keep high count)
$query = "DELETE FROM `bruteforce` WHERE (`updated` < (NOW() - INTERVAL 31 DAY)) AND (`count` < 1000)";
$result = $db->Execute($query) or die("Error in sql: $query. " . $db->ErrorMsg());

$mailbody .= "<br>Bruteforce deleted: ".$db->Affected_Rows();

// get number of high count (log in attempts)
$query = "SELECT COUNT(*) AS number FROM `bruteforce` WHERE (`count` > 999)";
$result = $db->Execute($query) or die("Error in sql: $query. " . $db->ErrorMsg());

$mailbody .= "<br>Bruteforce high count (>999): ".$result->fields['number'];

// delete accounts that has not been logged in and verified and is over 24 hous old
$query = "DELETE FROM `users` WHERE `created` < (NOW() - INTERVAL 1 DAY) AND `emailconfirm` = 0 AND `lastlogin` = '0000-00-00'"; 
$result = $db->Execute($query) or die("Error in sql: $query. " . $db->ErrorMsg());

$mailbody .= "<br>Users deleted (no email confirmation): ".$db->Affected_Rows();

$json = new Services_JSON();
$basedir = dirname(__FILE__)."/";
$md5filename = $basedir."tmp/filehash.md5";

// without trailing '/'
$md5excludearray = array(
"/home/e-smith/files/ibays/pass_ibay/html/phpBB/cache",
"/home/e-smith/files/ibays/pass_ibay/html/help"
);
$md5array = array();
MD5readfolder($basedir, $md5excludearray, $md5array);

if(isset($_GET['md5']))
{
	$fh = fopen($md5filename, 'w') or die("can't open file");	
	fwrite($fh, $json->encode($md5array));
	$mailbody .= "<br><br>MD5 file hash generated values: ".count($md5array);
	foreach($md5array as $key => $value) 
	{
		$mailbody .= "<br>".$key." = ".$value;
	}
}
else
{
	$fh = fopen($md5filename, 'r') or die("can't open file");
	$md5refarray = (array)$json->decode(fread($fh, filesize($md5filename)));
	$md5referrors = "";
	foreach($md5array as $key => $value) 
	{
		if($md5refarray[$key] != $value)
			$md5referrors .= "<br>".$key.": ".$value;
	}
	if(strlen($md5referrors))
	{
		$mailbody .= "<br><br>MD5 FILE HASH VALUES THAT IS NOT EQUAL TO REFERENCE: ".count($md5array).$md5referrors;
	}
	else
	{
		$mailbody .= "<br>All files have correct MD5 values: ".count($md5array);
	}
}
fclose($fh);

$mailbody .= "<br><br>THE END";
$sapi_type = php_sapi_name();

if (substr($sapi_type, 0, 3) == 'cgi')
{
	print strip_tags(preg_replace("/<br>/", "\r\n", $mailbody));
	foreach ( $argv as $key => $value) 
	{
		if($key > 0) 
			mailoutput($value, $mailbody);
	} 
}
else
{
	print $mailbody;
	if(isset($_GET['email']))
		mailoutput($_GET['email'], $mailbody);	
}

?>
