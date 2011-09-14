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

require_once("pcrypt.config.php");
require_once("adodb_lite/adodb.inc.php");
require_once("json.inc.php");
require_once("phpmailer/class.phpmailer.php");

function my_rand($length = 23)
{
	$fp = fopen('/dev/urandom','rb');
	if ($fp !== FALSE) 
	{
    	$pr_bits = fread($fp, $length);
    	fclose($fp);
    	
    	return $pr_bits;
	}
	else
	{
		return uniqid(mt_rand(), true);
	}
}

function getrealipaddr()
{
    if (!empty($_SERVER['HTTP_CLIENT_IP']))   //check ip from share internet
    {
      $ip=$_SERVER['HTTP_CLIENT_IP'];
    }
    elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR']))   //to check ip is pass from proxy
    {
      $ip=$_SERVER['HTTP_X_FORWARDED_FOR'];
    }
    else
    {
      $ip=$_SERVER['REMOTE_ADDR'];
    }
    return $ip;
}

function brute_force_delay($db, $crypt)
{	
	// test if crypt exist
	$query = "SELECT COUNT(*) AS CRYPTCOUNT FROM `users` WHERE `usercrypt`=".$db->Qmagic($crypt);
	$result = $db->Execute($query) or die("Error in database query: $query. " . $db->ErrorMsg());	
	
	if($result->fields['CRYPTCOUNT'] == 0)
	{
		$ip = getrealipaddr();

		$query = "SELECT count, UNIX_TIMESTAMP(updated) AS updated_unix FROM `bruteforce` WHERE `ip`='".$ip."' LIMIT 1";
		$result = $db->Execute($query) or trigger_error("Error in database SQL: ".$query." => ".$db->ErrorMsg(), E_USER_ERROR);

		$count = $result->fields['count'] + 1;
		$updated = $result->fields['updated_unix'];

		if($count > 1)
		{
			$query = "UPDATE `bruteforce` SET count=".$count.", usercrypt=".$db->Qmagic($crypt)." WHERE `ip`='".$ip."'";
			$resultnew = $db->Execute($query) or trigger_error("Error in database SQL: ".$query." => ".$db->ErrorMsg(), E_USER_ERROR);
		}
		else
		{    
			$query = "INSERT INTO `bruteforce` (`ip`, `count`, `usercrypt`) VALUES ('".$ip."', 1, ".$db->Qmagic($crypt).")";
			$resultnew = $db->Execute($query) or trigger_error("Error in database SQL: ".$query." => ".$db->ErrorMsg(), E_USER_ERROR);
		}
    
		$timediff = time() - $updated;

		if($timediff < 1)
		$timediff = 1;

		$max = (500000*$count)/$timediff;

		if($max < 1000000)
		  $max = 1000000;
		  
		if($max > 20000000)
		  $max = 20000000; 

		// use some time (prevent brute force attack)
		usleep(mt_rand(500000, $max));

		return true;
	}
	else
  		return false;	
}

function sendcomfirmemail($to, $from, $subject, $mailbody)
{
	$mail = new PHPMailer();
	$mail->IsMail();
	$mail->SetLanguage("en");
	$mail->IsHTML(true);
	$mail->FromName = $from; 
	$mail->From = $from;
	//$mail->AddReplyTo($from);
	$mail->Subject = $subject;
	$mail->WordWrap = 50;
	$mail->CharSet = 'UTF-8';

	$mail->MsgHTML($mailbody);
	$mail->AltBody = strip_tags(preg_replace("/<br>/", "\r\n", $mailbody));
	$mail->AddAddress($to);

	return $mail->Send();
}

function getusercrypt($db, $session)
{
	// get loginsession
	$query = "SELECT id FROM `sessions` WHERE `value` = ".$db->Qmagic($session)." AND `key` = 'session' LIMIT 1";
	if(false == ($result = $db->Execute($query)))
		return "SQLERROR";

	if($result->RecordCount() == 1)
	{
		return $result->fields['id'];
	}
	else
	{
		brute_force_delay($db, "getusercrypt"); // delay somebody that try to steal the session (no use - but anyway)
		return "NOSESSIONFOUND";
	}
}

function makereply($json, $id, $result, $error)
{
	if($error == 4) // do not reveal database errors (info about the system)
	{
		trigger_error($result, E_USER_WARNING);
		$result = "Error in database SQL - please contact administrator!";
	}
	
	$replyjson = array();

	$replyjson['result'] = $result;
	$replyjson['error'] = $error;
	$replyjson['id'] = $id;

	return $json->encode($replyjson);
}

?>
