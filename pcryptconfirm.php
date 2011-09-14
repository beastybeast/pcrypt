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

require_once($folder."pcrypt.inc.php");

$db = ADONewConnection($db_system);
$result = $db->Connect($db_server, $db_user, $db_password, $db_database) or die("Unable to connect to DB");

$dbid = $_GET['id'];
$confirmstring = $_GET['confirmstring'];
$replyurl = $_GET['replyurl'];
$action = $_GET['action'];

$query = "SELECT users.*, UNIX_TIMESTAMP(users.confirm) AS confirm_unix, UNIX_TIMESTAMP(NOW()) AS now_unix FROM `users` WHERE `id`=".$db->Qmagic($dbid);
$result = $db->Execute($query) or die("Error in sql: $query. " . $db->ErrorMsg());

if($result->RecordCount() != 1)
	redirectfunction(1);

$emailconfirmstring = $result->fields['emailconfirmstring'];
$emailconfirm = $result->fields['emailconfirm'];
$confirm = $result->fields['confirm_unix'];
$now = $result->fields['now_unix'];
$usercrypt = $result->fields['usercrypt'];

if($emailconfirmstring != $confirmstring)
{
	brute_force_delay($db, "pcryptconfirm"); // delay somebody that try to update/delete random
	redirectfunction(2);
}

if($now > ($confirm + 86400)) // 24 hours
	redirectfunction(5);

switch($action)
{	
	default:
		redirectfunction(7);
	break;

	case "update":
	case "create":	
		if($emailconfirm != 0)
			redirectfunction(3);		

		$update = "UPDATE `users` SET emailconfirm=1 WHERE id=".$db->Qmagic($dbid);
		$result = $db->Execute($update) or trigger_error("Error in database SQL: ".$query." => ".$db->ErrorMsg(), E_USER_ERROR);

		if($db->Affected_Rows() == 0)
			redirectfunction(4);
	break;
	
	case "delete":		
		$delete = "DELETE FROM `data` WHERE userid=".$db->Qmagic($dbid);
		$result = $db->Execute($delete) or trigger_error("Error in database SQL: ".$query." => ".$db->ErrorMsg(), E_USER_ERROR);

		$delete = "DELETE FROM `users` WHERE id=".$db->Qmagic($dbid);
		$result = $db->Execute($delete) or trigger_error("Error in database SQL: ".$query." => ".$db->ErrorMsg(), E_USER_ERROR);

		if($db->Affected_Rows() == 0)
			redirectfunction(6);
	break;	
}

redirectfunction(0);

function redirectfunction($errorid)
{
	global $replyurl;
	global $action;

	$replyurl .= "?action=".$action;

	if($errorid > 0)
	{
		$replyurl .= "&errorid=".$errorid."&errorstring=";

		switch($errorid)
		{
			case 1: $replyurl .= urlencode("Unknown account (not found)"); break;
			case 2: $replyurl .= urlencode("Unknown confirm string"); break;
			case 3: $replyurl .= urlencode("The account have already been activated"); break;
			case 4: $replyurl .= urlencode("Unknown account activation error"); break;
			case 5: $replyurl .= urlencode("Email confirmation is too late (more than 24 hours since the account change was requested)"); break;
			case 6: $replyurl .= urlencode("Unable to delete account"); break;
			case 7: $replyurl .= urlencode("Unknown action specified"); break;
		}
	}

	header("HTTP/1.1 301 Moved Permanently");
	header("Location: ".$replyurl);
	die();
}

?>
