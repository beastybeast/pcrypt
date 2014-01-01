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

require_once("pcrypt.inc.php");
require_once("sha256.inc.php");
require_once("captcha.inc.php");

header("Content-type: application/json; charset=utf-8");

// Allow from any origin
if (isset($_SERVER['HTTP_ORIGIN'])) 
{
    header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Max-Age: 86400');    // cache for 1 day
}

// Access-Control headers are received during OPTIONS requests
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') 
{
    if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD']))
        header("Access-Control-Allow-Methods: GET, POST, OPTIONS");         

    if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']))
        header("Access-Control-Allow-Headers:        {$_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']}");

    exit(0);
}

$errorstringarray = array(
    1 => "Unable to connect to DB", 
    2 => "Unknown method specified", 
    3 => "Wrong number of arguments",
    4 => "Error in database SQL: ",
    5 => "Wrong captcha number specified", 
    6 => "Account already exist",
    7 => "Unknown user", 
    8 => "Email is not the same",
    9 => "Email not validated", 
    10 => "Client checksum is not validated",
    11 => "Unknown error", 
    12 => "No records found or affected: ",
    13 => "Mail Error: ", 
    14 => "User is not validated"
  );

$postdata = $HTTP_RAW_POST_DATA;
$json = new Services_JSON();

$jsondata = $json->decode($postdata);

$method = $jsondata->method;
$session = $jsondata->params[0];
$dataname = $jsondata->params[1];
$data = $jsondata->params[2];
$id = $jsondata->id;

//trigger_error("DATA: ".$postdata);

$db = ADONewConnection($db_system);
$result = $db->PConnect($db_server, $db_user, $db_password, $db_database) or die(makereply($json, $id, $errorstringarray[1], 1));

switch($method)
{
	default:
		die(makereply($json, $id, $errorstringarray[2], 2));
	break;

	case 'captcha':
		if(count($data) != 3)
			die(makereply($json, $id, $errorstringarray[3], 3));

		$resultarray = array();
		$captcha = new CaptchaNumber($data[0], $data[1], $data[2]);

		$resultarray[0] = sha256(my_rand() . microtime()); // session ID
		$resultarray[1]  = base64_encode($captcha->GetImage());
	
		$query = "INSERT INTO `sessions` (`id`, `key`, `value`) VALUES ('".$resultarray[0]."', 'captcha', '".$captcha->GetNumber()."') ON DUPLICATE KEY UPDATE value = '".$captcha->GetNumber()."'";	
		$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));

		if($db->Affected_Rows() == 0)
			die(makereply($json, $id, $errorstringarray[12].substr($query, 0, 200), 12));
    
		die(makereply($json, $id, $resultarray, null)); 
	break;

	case 'create':
		if(count($data) != 9)
			die(makereply($json, $id, $errorstringarray[3], 3));
			
		usleep(mt_rand(500000, 1000000)); // prevent some possible brute force attacks

		$query = "SELECT value FROM `sessions` WHERE `id`=".$db->Qmagic($data[3])." AND `key`='captcha' LIMIT 1";
		$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));
		
		if($data[2] != $result->fields['value'])
		{
			die(makereply($json, $id, $errorstringarray[5], 5));
		}
		
		$emailconfirmstring = sha256(my_rand() . $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);		
		$salt = sha256(my_rand() . $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT'] . time());
		$cryptid = sha256(my_rand() . time());

		$query = "SELECT COUNT(*) AS PriorUserCrypt FROM `users` WHERE `usercrypt`=".$db->Qmagic($data[0]);
		$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));

		if($result->fields['PriorUserCrypt'] != 0)
		{
			die(makereply($json, $id, $errorstringarray[6], 6));
		}

		$query = "INSERT INTO `users` (`usercrypt`, `email`, `salt`, `cryptid`, `emailconfirmstring`, `created`, `confirm`) VALUES (".$db->Qmagic($data[0]).", ".$db->Qmagic($data[1]).", '".$salt."', '".$cryptid."', '".$emailconfirmstring."', NOW(), NOW())";
		$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));

		if($db->Affected_Rows() == 0)
			die(makereply($json, $id, $errorstringarray[12].substr($query, 0, 200), 12));

		$mailbody = $data[6];					
		$trans = array();
		$trans['[confirmurl]'] = "http://".$_SERVER['HTTP_HOST']."/pcryptconfirm.php?id=".$db->Insert_ID()."&confirmstring=".$emailconfirmstring."&replyurl=".$data[7]."&action=create";
		$mailbody = strtr($mailbody, $trans);

		if(!sendcomfirmemail($data[1], $data[5], $data[4], $mailbody))
			die(makereply($json, $id, $errorstringarray[13].$mail->ErrorInfo, 13));

		$query = "DELETE FROM `sessions` WHERE `id` = ".$db->Qmagic($data[3])." AND `key`='captcha'";
		$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));
		
		if($data[8] == true)
		{
			$createsession = sha256(my_rand() . $_SERVER['REMOTE_ADDR'] . time()); // allow copy to newly created account
		
			$query = "INSERT INTO `sessions` (`id`, `key`, `value`) VALUES (".$db->Qmagic($data[0]).", 'session', '".$createsession."') ON DUPLICATE KEY UPDATE value = '".$createsession."'";	
			$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));

			if($db->Affected_Rows() == 0)
				die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));
				
			$resultarray = array();

		$resultarray[0] = $createsession;
		$resultarray[1] = $salt;		

			die(makereply($json, $id, $resultarray, null)); 
		}
		else
		{
			die(makereply($json, $id, true, null)); 
		}
	break;

	case 'delete':
		if(brute_force_delay($db, $data[0]))
			die(makereply($json, $id, $errorstringarray[7], 7));

		if(count($data) != 8)
			die(makereply($json, $id, $errorstringarray[3], 3));

		$query = "SELECT value FROM `sessions` WHERE `id`=".$db->Qmagic($data[3])." AND `key`='captcha' LIMIT 1";
		$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));
		
		if($data[2] != $result->fields['value'])
		{
			die(makereply($json, $id, $errorstringarray[5], 5));
		}
		
		$emailconfirmstring = sha256(my_rand() . $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);		

		$query = "SELECT * FROM `users` WHERE `usercrypt`=".$db->Qmagic($data[0])." LIMIT 1";
		$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));

		if($result->RecordCount() != 1)	
			die(makereply($json, $id, $errorstringarray[12].substr($query, 0, 200), 12));

		if($result->fields['email'] != $data[1])
			die(makereply($json, $id, $errorstringarray[8], 8));

		$dbid = $result->fields['id'];

		$query = "UPDATE `users` SET emailconfirmstring='".$emailconfirmstring."', confirm=NOW() WHERE usercrypt=".$db->Qmagic($data[0]);
		$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));

		if($db->Affected_Rows() == 0)
			die(makereply($json, $id, $errorstringarray[12].substr($query, 0, 200), 12));

		$mailbody = $data[6];					
		$trans = array();
		$trans['[confirmurl]'] = "http://".$_SERVER['HTTP_HOST']."/pcryptconfirm.php?id=".$dbid."&confirmstring=".$emailconfirmstring."&replyurl=".$data[7]."&action=delete";
		$mailbody = strtr($mailbody, $trans);

		if(!sendcomfirmemail($data[1], $data[5], $data[4], $mailbody))
			die(makereply($json, $id, $errorstringarray[13].$mail->ErrorInfo, 13));

		$query = "DELETE FROM `sessions` WHERE `id` = ".$db->Qmagic($data[3])." AND `key`='captcha'";
		$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));

		die(makereply($json, $id, true, null)); 
	break;

	case 'update':
		if(brute_force_delay($db, $data[0]))
			die(makereply($json, $id, $errorstringarray[7], 7));

		if(count($data) != 8)
			die(makereply($json, $id, $errorstringarray[3], 3));

		$query = "SELECT value FROM `sessions` WHERE `id`=".$db->Qmagic($data[3])." AND `key`='captcha' LIMIT 1";
		$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));
		
		if($data[2] != $result->fields['value'])
		{
			die(makereply($json, $id, $errorstringarray[5], 5));
		}
		
		$emailconfirmstring = sha256(my_rand() . $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);		

		$query = "SELECT users.* FROM `users` WHERE `usercrypt`=".$db->Qmagic($data[0])." LIMIT 1";
		$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));

		if($result->RecordCount() != 1)	
			die(makereply($json, $id, $errorstringarray[12].substr($query, 0, 200), 12));

		$dbid = $result->fields['id'];

		$query = "UPDATE `users` SET email=".$db->Qmagic($data[1]).", emailconfirm=0, emailconfirmstring='".$emailconfirmstring."', confirm=NOW() WHERE usercrypt=".$db->Qmagic($data[0]);
		$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));

		if($db->Affected_Rows() == 0)
			die(makereply($json, $id, $errorstringarray[12].substr($query, 0, 200), 12));

		$mailbody = $data[6];					
		$trans = array();
		$trans['[confirmurl]'] = "http://".$_SERVER['HTTP_HOST']."/pcryptconfirm.php?id=".$dbid."&confirmstring=".$emailconfirmstring."&replyurl=".$data[7]."&action=update";
		$mailbody = strtr($mailbody, $trans);

		if(!sendcomfirmemail($data[1], $data[5], $data[4], $mailbody))
			die(makereply($json, $id, $errorstringarray[13].$mail->ErrorInfo, 13));

		$query = "DELETE FROM `sessions` WHERE `id` = ".$db->Qmagic($data[3])." AND `key`='captcha'";
		$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));

		die(makereply($json, $id, true, null)); 
	break;
	
	case 'login':
		if(brute_force_delay($db, $data))
			die(makereply($json, $id, $errorstringarray[7], 7));

		// get some user values
		$query = "SELECT salt, created, lastlogin, emailconfirm FROM `users` WHERE `usercrypt`=".$db->Qmagic($data)." LIMIT 1";
		$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));

		if($result->RecordCount() != 1)	
			die(makereply($json, $id, $errorstringarray[12].substr($query, 0, 200), 12));

		if($result->fields['emailconfirm'] == 0)	
			die(makereply($json, $id, $errorstringarray[9], 9));

		$resultarray = array();

		$resultarray[0] = sha256(my_rand() . $_SERVER['HTTP_USER_AGENT'] . microtime()); // session ID
		$resultarray[1] = $result->fields['salt'];
		$resultarray[2] = $result->fields['created'];
		$resultarray[3] = $result->fields['lastlogin'];
	
		$query = "INSERT INTO `sessions` (`id`, `key`, `value`) VALUES (".$db->Qmagic($data).", 'session', '".$resultarray[0]."') ON DUPLICATE KEY UPDATE value = '".$resultarray[0]."'";	
		$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));

		if($db->Affected_Rows() == 0)
			die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));		

		$query = "UPDATE `users` SET users.lastlogin = NOW() WHERE users.usercrypt = ".$db->Qmagic($data);
		$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));

		if($db->Affected_Rows() == 0)
			die(makereply($json, $id, $errorstringarray[12].substr($query, 0, 200), 12));
    
		die(makereply($json, $id, $resultarray, null)); 
	break;
	
	case 'logout':
		// delete loginsession in session db
		$query = "DELETE FROM `sessions` WHERE `value` = ".$db->Qmagic($session)." AND `key`='session'";
		$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));

		die(makereply($json, $id, true, null));  
	break;

	case 'ping':
    $usercrypt = getusercrypt($db, $session);
    
    if($usercrypt == false)
      die(makereply($json, $id, $errorstringarray[14], 14));
    else
      die(makereply($json, $id, true, null));	
	break;
  
	case 'getdata':
    $usercrypt = getusercrypt($db, $session);
    
    if($usercrypt == false)
      die(makereply($json, $id, $errorstringarray[14], 14));
	
		$query = "SELECT data.data FROM data, users WHERE users.usercrypt = '".$usercrypt."' AND data.userid = users.id AND data.name = ".$db->Qmagic($dataname)." LIMIT 1";	
		$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));

		$resultarray = array();		

		if($result->RecordCount() != 1)
			$resultarray[0] = "";
		else	
			$resultarray[0] = $result->fields['data'];
		
		$resultarray[1] = crc32($resultarray[0]);

		die(makereply($json, $id, $resultarray, null));	
	break;

	case 'setdata':
		if(count($data) != 2)
			die(makereply($json, $id, $errorstringarray[3], 3));
		
		if($data[1] != crc32($data[0]))
			die(makereply($json, $id, $errorstringarray[10], 10));
			
    $usercrypt = getusercrypt($db, $session);
    
    if($usercrypt == false)
      die(makereply($json, $id, $errorstringarray[14], 14));

		$query = "INSERT INTO data (userid, name, data) SELECT id AS userid, ".$db->Qmagic($dataname).", ".$db->Qmagic($data[0])." FROM users WHERE usercrypt = '".$usercrypt."' ON DUPLICATE KEY UPDATE data = ".$db->Qmagic($data[0]);	
		$result = $db->Execute($query) or die(makereply($json, $id, $errorstringarray[4].substr($query, 0, 200)." => ".$db->ErrorMsg(), 4));

		if($db->Affected_Rows() == 0)
			die(makereply($json, $id, $errorstringarray[12].substr($query, 0, 200), 12));

		die(makereply($json, $id, true, null));	

	break;
}

die(makereply($json, $id, $errorstringarray[11], 11));	

?>
