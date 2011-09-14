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
$result = $db->PConnect($db_server, $db_user, $db_password, $db_database) or die(makereply($json, $id, "Unable to connect to DB", 1));

switch($method)
{
	default:
		die(makereply($json, $id, 'Unknown method specified', 2));
	break;

	case 'captcha':
		if(count($data) != 3)
			die(makereply($json, $id, "Wrong number of arguments", 3));

		$resultarray = array();
		$captcha = new CaptchaNumber($data[0], $data[1], $data[2]);

		$resultarray[0] = sha256(my_rand() . microtime()); // session ID
		$resultarray[1]  = base64_encode($captcha->GetImage());
	
		$query = "INSERT INTO `sessions` (`id`, `key`, `value`) VALUES ('".$resultarray[0]."', 'captcha', '".$captcha->GetNumber()."') ON DUPLICATE KEY UPDATE value = '".$captcha->GetNumber()."'";	
		$result = $db->Execute($query) or die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));

		if($db->Affected_Rows() == 0)
			die(makereply($json, $id, "No records found or affected: ".$query, 12));
    
		die(makereply($json, $id, $resultarray, null)); 
	break;

	case 'create':
		if(count($data) != 8)
			die(makereply($json, $id, "Wrong number of arguments", 3));

		$query = "SELECT value FROM `sessions` WHERE `id`=".$db->Qmagic($data[3])." AND `key`='captcha' LIMIT 1";
		$result = $db->Execute($query) or die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));
		
		if($data[2] != $result->fields['value'])
		{
			die(makereply($json, $id, "Wrong number specified", 5));
		}
		
		$emailconfirmstring = sha256(my_rand() . $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);		
		$salt = sha256(my_rand() . $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT'] . time());
		$cryptid = sha256(my_rand() . time());

		$query = "SELECT COUNT(*) AS PriorUserCrypt FROM `users` WHERE `usercrypt`=".$db->Qmagic($data[0]);
		$result = $db->Execute($query) or die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));

		if($result->fields['PriorUserCrypt'] != 0)
		{
			die(makereply($json, $id, "Account already exist", 6));
		}

		$query = "INSERT INTO `users` (`usercrypt`, `email`, `salt`, `cryptid`, `emailconfirmstring`, `created`, `confirm`) VALUES (".$db->Qmagic($data[0]).", ".$db->Qmagic($data[1]).", '".$salt."', '".$cryptid."', '".$emailconfirmstring."', NOW(), NOW())";
		$result = $db->Execute($query) or die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));

		if($db->Affected_Rows() == 0)
			die(makereply($json, $id, "No records found or affected: ".$query, 12));

		$mailbody = $data[6];					
		$trans = array();
		$trans['[confirmurl]'] = "http://pcrypt.org/pcryptconfirm.php?id=".$db->Insert_ID()."&confirmstring=".$emailconfirmstring."&replyurl=".$data[7]."&action=create";
		$mailbody = strtr($mailbody, $trans);

		if(!sendcomfirmemail($data[1], $data[5], $data[4], $mailbody))
			die(makereply("Mail Error: " . $mail->ErrorInfo, 13));

		$query = "DELETE FROM `sessions` WHERE `id` = ".$db->Qmagic($data[3])." AND `key`='captcha'";
		$result = $db->Execute($query) or die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));

		die(makereply($json, $id, true, null)); 
	break;

	case 'delete':
		if(brute_force_delay($db, $data[0]))
			die(makereply($json, $id, 'Unknown user', 7));

		if(count($data) != 8)
			die(makereply($json, $id, "Wrong number of arguments", 3));

		$query = "SELECT value FROM `sessions` WHERE `id`=".$db->Qmagic($data[3])." AND `key`='captcha' LIMIT 1";
		$result = $db->Execute($query) or die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));
		
		if($data[2] != $result->fields['value'])
		{
			die(makereply($json, $id, "Wrong number specified", 5));
		}
		
		$emailconfirmstring = sha256(my_rand() . $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);		

		$query = "SELECT * FROM `users` WHERE `usercrypt`=".$db->Qmagic($data[0])." LIMIT 1";
		$result = $db->Execute($query) or die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));

		if($result->RecordCount() != 1)	
			die(makereply($json, $id, "No records found or affected: ".$query, 12));

		if($result->fields['email'] != $data[1])
			die(makereply($json, $id, "Email is not the same", 8));

		$dbid = $result->fields['id'];

		$query = "UPDATE `users` SET emailconfirmstring='".$emailconfirmstring."', confirm=NOW() WHERE usercrypt=".$db->Qmagic($data[0]);
		$result = $db->Execute($query) or die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));

		if($db->Affected_Rows() == 0)
			die(makereply($json, $id, "No records found or affected: ".$query, 12));

		$mailbody = $data[6];					
		$trans = array();
		$trans['[confirmurl]'] = "http://pcrypt.org/pcryptconfirm.php?id=".$dbid."&confirmstring=".$emailconfirmstring."&replyurl=".$data[7]."&action=delete";
		$mailbody = strtr($mailbody, $trans);

		if(!sendcomfirmemail($data[1], $data[5], $data[4], $mailbody))
			die(makereply("Mail Error: " . $mail->ErrorInfo, 13));

		$query = "DELETE FROM `sessions` WHERE `id` = ".$db->Qmagic($data[3])." AND `key`='captcha'";
		$result = $db->Execute($query) or die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));

		die(makereply($json, $id, true, null)); 
	break;

	case 'update':
		if(brute_force_delay($db, $data[0]))
			die(makereply($json, $id, 'Unknown user', 7));

		if(count($data) != 8)
			die(makereply($json, $id, "Wrong number of arguments", 3));

		$query = "SELECT value FROM `sessions` WHERE `id`=".$db->Qmagic($data[3])." AND `key`='captcha' LIMIT 1";
		$result = $db->Execute($query) or die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));
		
		if($data[2] != $result->fields['value'])
		{
			die(makereply($json, $id, "Wrong number specified", 5));
		}
		
		$emailconfirmstring = sha256(my_rand() . $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);		

		$query = "SELECT users.* FROM `users` WHERE `usercrypt`=".$db->Qmagic($data[0])." LIMIT 1";
		$result = $db->Execute($query) or die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));

		if($result->RecordCount() != 1)	
			die(makereply($json, $id, "No records found or affected: ".$query, 12));

		$dbid = $result->fields['id'];

		$query = "UPDATE `users` SET email=".$db->Qmagic($data[1]).", emailconfirm=0, emailconfirmstring='".$emailconfirmstring."', confirm=NOW() WHERE usercrypt=".$db->Qmagic($data[0]);
		$result = $db->Execute($query) or die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));

		if($db->Affected_Rows() == 0)
			die(makereply($json, $id, "No records found or affected: ".$query, 12));

		$mailbody = $data[6];					
		$trans = array();
		$trans['[confirmurl]'] = "http://pcrypt.org/pcryptconfirm.php?id=".$dbid."&confirmstring=".$emailconfirmstring."&replyurl=".$data[7]."&action=update";
		$mailbody = strtr($mailbody, $trans);

		if(!sendcomfirmemail($data[1], $data[5], $data[4], $mailbody))
			die(makereply("Mail Error: " . $mail->ErrorInfo, 13));

		$query = "DELETE FROM `sessions` WHERE `id` = ".$db->Qmagic($data[3])." AND `key`='captcha'";
		$result = $db->Execute($query) or die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));

		die(makereply($json, $id, true, null)); 
	break;
	
	case 'login':
		if(brute_force_delay($db, $data))
			die(makereply($json, $id, 'Unknown user', 7));

		// get some user values
		$query = "SELECT salt, created, lastlogin, emailconfirm FROM `users` WHERE `usercrypt`=".$db->Qmagic($data)." LIMIT 1";
		$result = $db->Execute($query) or die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));

		if($result->RecordCount() != 1)	
			die(makereply($json, $id, "No records found or affected: ".$query, 12));

		if($result->fields['emailconfirm'] == 0)	
			die(makereply($json, $id, 'Email not validated', 9));

		$resultarray = array();

		$resultarray[0] = sha256(my_rand() . $_SERVER['HTTP_USER_AGENT'] . microtime()); // session ID
		$resultarray[1] = $result->fields['salt'];
		$resultarray[2] = $result->fields['created'];
		$resultarray[3] = $result->fields['lastlogin'];
	
		$query = "INSERT INTO `sessions` (`id`, `key`, `value`) VALUES (".$db->Qmagic($data).", 'session', '".$resultarray[0]."') ON DUPLICATE KEY UPDATE value = '".$resultarray[0]."'";	
		$result = $db->Execute($query) or die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));

		if($db->Affected_Rows() == 0)
			die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));		

		$query = "UPDATE `users` SET users.lastlogin = NOW() WHERE users.usercrypt = ".$db->Qmagic($data);
		$result = $db->Execute($query) or die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));

		if($db->Affected_Rows() == 0)
			die(makereply($json, $id, "No records found or affected: ".$query, 12));
    
		die(makereply($json, $id, $resultarray, null)); 
	break;
	
	case 'logout':
		// delete loginsession in session db
		$query = "DELETE FROM `sessions` WHERE `value` = ".$db->Qmagic($session)." AND `key`='session'";
		$result = $db->Execute($query) or die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));

		die(makereply($json, $id, true, null));  
	break;

	case 'getdata':
		$query = "SELECT data.data FROM data, users WHERE users.usercrypt = '".getusercrypt($db, $session)."' AND data.userid = users.id AND data.name = ".$db->Qmagic($dataname)." LIMIT 1";	
		$result = $db->Execute($query) or die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));

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
			die(makereply($json, $id, "Wrong number of arguments", 3));
		
		if($data[1] != crc32($data[0]))
			die(makereply($json, $id, 'Client checksum is not validated', 10));

		$query = "INSERT INTO data (userid, name, data) SELECT id AS userid, ".$db->Qmagic($dataname).", ".$db->Qmagic($data[0])." FROM users WHERE usercrypt = '".getusercrypt($db, $session)."' ON DUPLICATE KEY UPDATE data = ".$db->Qmagic($data[0]);	
		$result = $db->Execute($query) or die(makereply($json, $id, "Error in database SQL: ".$query." => ".$db->ErrorMsg(), 4));

		if($db->Affected_Rows() == 0)
			die(makereply($json, $id, "No records found or affected: ".$query, 12));

		die(makereply($json, $id, true, null));	

	break;
}

die(makereply($json, $id, 'Unknown error', 11));	

?>
