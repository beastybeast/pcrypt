/*

    PasswordCrypt - online password store
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

function validatepassobject(passobj)
{
	//passobj.id = findnextid(passArr); ??
	
	if(typeof(passobj.cre) != 'number')
		passobj.cre = (new Date()).getTime();
	if(typeof(passobj.upd) != 'number')
		passobj.upd = (new Date()).getTime();

	if(typeof(passobj.gid) != 'number')
		if(passobj.gid) passobj.gid = Number(passobj.gid);
		else passobj.gid = 0;

	if(typeof(passobj.name) != 'string')
		if(passobj.name) passobj.name = passobj.name.toString();
		else passobj.name = '';

	if(typeof(passobj.user) != 'string')
		if(passobj.user) passobj.user = passobj.user.toString();
		else passobj.user = '';

	if(typeof(passobj.pass) != 'string')
		if(passobj.pass) passobj.pass = passobj.pass.toString();
		else passobj.pass = '';

	if(typeof(passobj.url) != 'string')
		if(passobj.url) passobj.url = passobj.url.toString();
		else passobj.url = '';

	if(typeof(passobj.note) != 'string')
		if(passobj.note) passobj.note = passobj.note.toString();
		else passobj.note = '';

	if(passobj.name.length > 63)
		passobj.name = passobj.name.substring(0, 63);
	if(passobj.user.length > 63)
		passobj.user = passobj.user.substring(0, 63);
	if(passobj.pass.length > 63)
		passobj.pass = passobj.pass.substring(0, 63);
	if(passobj.url.length > 255)
		passobj.url = passobj.url.substring(0, 63);
	if(passobj.note.length > 255)
		passobj.note = passobj.note.substring(0, 63);

	return passobj;
}

function validategroupobject(groupobj)
{
	//groupobj.id = findnextid(passArr); ??
	
	if(typeof(groupobj.cre) != 'number')
		groupobj.cre = (new Date()).getTime();
	if(typeof(groupobj.upd) != 'number')
		groupobj.upd = (new Date()).getTime();

	if(typeof(groupobj.name) != 'string')
		if(passobj.name) passobj.name = passobj.name.toString();
		else passobj.name = '';

	if(groupobj.name.length > 63)
		passobj.name = passobj.name.substring(0, 63);

	return groupobj;
}

function convertobjtoarray(obj)
{
	// return Array.prototype.slice.call(obj, 0); // does not work

	var array = [];

	for (var key in obj)
	if(obj.hasOwnProperty(key))
		array.push(obj[key]);  
   
	return array; 
} 

function exportarraycsv(array, items)
{
	var exportArr = [];

	// get object item names from first array item
	exportArr[0] = [];
	for (var name in array[0])
	{
		exportArr[0].push(name);
	}

	for (var i = 0; i < array.length; i++)
	for (var j = 0; j < items.length; j++)
	if(items[j] == array[i].id)
	{
		exportArr.push(convertobjtoarray(array[i]));
	}

	return CSV.arrayToCsv(exportArr);

	//csvstring = csvstring.replace(/\n/g, '<br>');
} 

function validemail(email) 
{
	var emailPattern = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;  
	
	return emailPattern.test(email); 
}

function testvalidlogin() // user may have opened a new tab (not legal as it erases sessionStorage for the new tab)
{
	if(!definedcryptkey()) 
	{	
		top.location.replace(window.location.protocol + '//' + window.location.host + '/login.php'); 
	}
}

// Array Remove - By John Resig (MIT Licensed)
Array.prototype.remove = function(from, to) 
{
	var rest = this.slice((to || from) + 1 || this.length);
	this.length = from < 0 ? this.length + from : from;
	return this.push.apply(this, rest);
};

function findid(array, id)
{
	for (var i = 0; i < array.length; i++)
	if(array[i].id == id)
		return i;
}

function findnextid(array)
{
	var nextid = 0;

	for (var i = 0; i < array.length; i++)
	if(array[i].id > nextid)
		nextid = array[i].id;

	return nextid + 1;
}

function jsonrpc(method, usercrypt, dataname, data, id, callback)
{
	var tmpObj = {};
	var tmpArr = [];

	tmpObj.method = method;
	tmpArr[0] = usercrypt;
	tmpArr[1] = dataname;
	tmpArr[2] = data;
	//tmpArr[3] = Sha256.hash(tmpArr[1]);
	tmpObj.params = tmpArr;
	tmpObj.id = id;

	function jsonrpcreply(http)
	{
		if(http.status == 200)
		{
			try 
			{
				var tmpObjreply = JSON.parse(http.responseText);
				//var finalresult = JSON.parse(tmpObjreply.result[0]);

				if(1)//if(tmpObjreply.result[1] == Sha256.hash(tmpObjreply.result[0]))
				{
					if(callback)
				      		callback(tmpObjreply.result[0], tmpObjreply.error, tmpObjreply.id);
				}
				else
				{
					if(callback)
				      		callback('Server checksum is not correct', 'crc', null);
				}
			}
			catch(e)
			{
				if(callback)
					callback('Exception in parsing', 'json', null);
			}
		}
		else
		{
			if(callback)
				callback('HTTP returned status: ' + http.status, 'http', tmpObjreply.id);
		}
	}

	jsoncom('jsoncom.php', JSON.stringify(tmpObj), jsonrpcreply);
}

function jsoncom(url, data, dofunc)
{
	var http = new XMLHttpRequest();

	http.open("POST", url, true); // POST mean almost unlimited data size

	//Send the proper header information along with the request
	http.setRequestHeader("Content-type", "application/json");	
	http.setRequestHeader("Content-length", data.length);
	http.setRequestHeader("Connection", "close");

	http.onreadystatechange = function() // Call a function when the state changes.
	{
		if(dofunc) 
		if(http.readyState == 4)
		{			
			dofunc(http);
		}
	}
	http.send(data);
}

function getarray(sessioncrypt, saltcrypt, arrayname)
{
	try
	{
		var data = getvalue(arrayname);

		if(!data || !data.length)
			return []; // empty array

		var array = JSON.parse(decryptstring(sessioncrypt, saltcrypt, data));

		if(!array || !array.length)
			return []; // empty array

		return array;
	}
	catch(e)
	{
		return false;
	}	
}

function setarray(usercrypt, sessioncrypt, saltcrypt, arrayname, array, id, callback)
{
	try
	{
		var data = encryptstring(sessioncrypt, saltcrypt, JSON.stringify(array));

		setvalue(arrayname, data);
		jsonrpc('setdata', usercrypt, arrayname, data, id, callback);

		return true;
	}
	catch(e)
	{
		return false;
	}		 
}

function sessionstorageexist() 
{
	try 
	{
		if(typeof(localStorage) == 'undefined') // for some strange reason we need to test on localStorage if cookies is disabled (sessionStorage is in a way undefined - but unable to test in firefox)
			return false;
	
		return 'sessionStorage' in window && window['sessionStorage'] !== null;
  	} 
	catch(e)
	{
		return false;
	}
}

function setvalue(key, value)
{
	if(sessionstorageexist())
	{
		sessionStorage[key] = JSON.stringify(value);
		return;
	}

	if(top.name.length)
		var tmpObj = JSON.parse(top.name);
	else
		var tmpObj = {};
	
	tmpObj[key] = value;
	
	top.name = JSON.stringify(tmpObj);
}

function getvalue(key)
{
	if(sessionstorageexist())
	{
		return JSON.parse(sessionStorage[key]);
	}

	if(!top.name.length)
		return false;

	var tmpObj = JSON.parse(top.name);

	return tmpObj[key];
}

function definedvalue(key)
{
	if(sessionstorageexist())
	{
		return (typeof(sessionStorage[key]) == "string") ?  true : false;			
	}
	
	if(!top.name.length)
		return false;

	var tmpObj = JSON.parse(top.name);

	return (typeof(tmpObj[key]) == "string") ?  true : false;	
}

function deletevalue(key)
{
	if(sessionstorageexist())
	{
		delete sessionStorage[key];
		return;
	}

	if(!top.name.length)
		return false;

	var tmpObj = JSON.parse(top.name);

	delete tmpObj[key];

	top.name = JSON.stringify(tmpObj);
}

function flushvalues()
{
	if(sessionstorageexist())
	{
		sessionStorage.clear()
	}
	
	top.name = "";
}

function deletecryptkey()
{
	flushvalues(); // just delete it all
}

function definedcryptkey()
{
	return definedvalue('cryptkey');
}

function setcryptkey(sessioncrypt, cryptkey)
{
	setvalue('cryptkey', Aes.Ctr.encrypt(Sha256.hash(cryptkey), sessioncrypt, 256)); // SHA256 hide length of key
}

function getcryptkey(sessioncrypt)
{
	return Aes.Ctr.decrypt(getvalue('cryptkey'), sessioncrypt, 256);
}

function aesusercipher(usertext, password) 
{
	if(!usertext.length || !password.length)
		return false;

	var nBytes = 256/8;  // no bytes in key
	var pwBytes = new Array(nBytes);
	var pt1Bytes = new Array(16); // 128 block size
	var pt2Bytes = new Array(16); // 128 block size
	
	// usertext has to be converted to hex SHA256 (256 bit)	
	usertext = Utf8.encode(Sha256.hash(usertext)); // is this utf8 needed ??
	password = Utf8.encode(password);

	// convert password to byte array
	for (var i = 0; i < nBytes; i++) 
	{
		pwBytes[i] = isNaN(password.charCodeAt(i)) ? 0 : password.charCodeAt(i);
	} 

	// convert usertext to byte array
	for (var i = 0; i < 16; i++) 
	{
		pt1Bytes[i] = parseInt(usertext.substring((i*2), (i*2)+2), 16);
		pt2Bytes[i] = parseInt(usertext.substring((i*2)+32, (i*2)+34), 16);   
	}
	  
	var cipherarray = Aes.cipher(pt1Bytes, Aes.keyExpansion(pwBytes));  // gives us 16-byte key
	cipherarray = cipherarray.concat(Aes.cipher(pt2Bytes, Aes.keyExpansion(pwBytes)));  // gives us 32-byte key

	// convert byte array to hex string array
	var ciphertxtarray = [];
	for (var i = 0; i < 32; i++) 
	{
		ciphertxtarray[i] = cipherarray[i].toString(16);
	}

	return ciphertxtarray.join('');
}

function buildtable(tablestyle, tablearrayheader, htmlarray) 
{
	//http://www.oreillynet.com/pub/a/javascript/2003/05/06/dannygoodman.html?page=2
	//http://www.oreillynet.com/javascript/2003/05/06/examples/dyn_table_benchmarker_ora.html
	
	var tablestring;
	var bgcolor;

	tablestring = "<table " + tablestyle + ">";

	tablestring += "<tr>";
	for (var i = 0, len_i = tablearrayheader.length; i < len_i; ++i) 
		tablestring += "<th " + tablearrayheader[i][1] + ">" + tablearrayheader[i][0];

	for (var i = 0, len_i = htmlarray.length; i < len_i; ++i)
	{
		tablestring += "<tr>";
		
		if(i%2)		
			bgcolor = "";
		else
			bgcolor = " style='background-color: #d8d8d8;'"; // e6e6e6 or d8d8d8
	
		for (var j = 0, len_j = htmlarray[i].length; j < len_j; ++j) 
			tablestring += "<td" + bgcolor + ">" + htmlarray[i][j];
	}

	tablestring += "</table>";

	return tablestring;
}

function encryptstring(sessioncrypt, saltcrypt, text)
{	
	var cryptkey = getcryptkey(sessioncrypt);

	if(cryptkey === false)
		return false;

	cryptkey = Sha256.hash(cryptkey + saltcrypt);

	return Aes.Ctr.encrypt(text, cryptkey, 256);
}

function decryptstring(sessioncrypt, saltcrypt, text)
{	
	var cryptkey = getcryptkey(sessioncrypt);

	if(cryptkey === false)
		return false;
	
	cryptkey = Sha256.hash(cryptkey + saltcrypt);

	return htmlspecialchars(Aes.Ctr.decrypt(text, cryptkey, 256), ['ENT_NOQUOTES']);
}

function decryptarray(sessioncrypt, saltcrypt, decryptarrayindex, dbarray)
{
	// arrays and objects are passed by reference as default (used here)

	var cryptkey = getcryptkey(sessioncrypt);

	if(cryptkey === false)
		return false;

	cryptkey = Sha256.hash(cryptkey + saltcrypt);

	for(var i = 0, len_i = dbarray.length; i < len_i; ++i)
	{	
		for(var j = 0, len_j = dbarray[i].length; j < len_j; ++j)
		if(decryptarrayindex[j])
			dbarray[i][j] = htmlspecialchars(Aes.Ctr.decrypt(dbarray[i][j], cryptkey, 256), ['ENT_NOQUOTES']);
		else
			dbarray[i][j] = dbarray[i][j];	
	}

	return true;
}

function randomString(stringlength) 
{
	var chars = "123456789ABCDEFGHIJKLMNPQRSTUVWXTZabcdefghiklmnpqrstuvwxyz";
	var randomstring = '';
	for (var i = 0; i < stringlength; i++) 
	{
		var rnum = Math.floor(Math.random() * chars.length);
		randomstring += chars.substring(rnum,rnum+1);
	}
	return randomstring;
}


function base64_url_encode(input)
{
	return strtr(input, '+/=', '-_,');
}

function base64_url_decode(input)
{
    return strtr(input, '-_,', '+/=');
}

function findgroupnameinarray(dbgarray, gid)
{
	for (var i=0 ; i < dbgarray.length ; i++)
	if(dbgarray[i].id == gid) 
		return dbgarray[i].name;

	return "";
}

function addgroupnameinarray(dbarray, dbgarray)
{
	for (var i=0 ; i < dbarray.length ; i++)
		dbarray[i].gnam = findgroupnameinarray(dbgarray, dbarray[i].gid);
}

function fillgroupselect(sessioncrypt, saltcrypt, selelement, selectedid, addall, addundef) 
{
	var grpArr = getarray(sessioncrypt, saltcrypt, 'groups');
	var currentindex = 0;
	
	selelement.length = 0; // remove all elements

	if(addall)
	{
		var selected = -1 == selectedid ? true : false;
		var op = new Option(addall, -1, selected, selected);
                selelement.options[selelement.options.length] = op;
		currentindex++;
	}

	if(addundef)
	{
		var selected = 0 == selectedid ? true : false;
		var op = new Option(addundef, 0, selected, selected);
                selelement.options[selelement.options.length] = op;
		currentindex++;
	}

	grpArr.sort(sortgrouparray);

	for (var i = 0, len_i = grpArr.length; i < len_i; ++i)
	{
		var selected = grpArr[i].id == selectedid ? true : false;
                var op = new Option(grpArr[i].name, grpArr[i].id, selected, selected);
                selelement.options[i + currentindex] = op;
        }	
}

function sortgrouparray(a, b)
{
	//http://www.javascriptkit.com/javatutors/arraysort.shtml

	var nameA, nameB;

	if(a.name)	
		nameA = a.name.toLowerCase();
	else
		nameA = "";

	if(b.name)
		nameB = b.name.toLowerCase();
	else
		nameB = "";	

	if (nameA < nameB) //sort string ascending
	  return -1
	if (nameA > nameB)
	  return 1
	return 0 //default return value (no sorting)
}

function copytoclipboard(cliptext)
{
	try
	{ 
		if (window.clipboardData)
		{
			// the IE-manier
			if(window.clipboardData.setData("Text", cliptext))
				return 0;
		}
		else if(navigator.userAgent.indexOf("Opera") != -1) 
		{
			// No know working method (need to detect it as it try netscape security with exception and also fail in execCommand with exception)
		}
		else if (window.netscape && netscape.security)
		{
			try
			{
				netscape.security.PrivilegeManager.enablePrivilege('UniversalXPConnect');
			}
			catch(err)
			{
				//https://addons.mozilla.org/firefox/addon/852/	
				//http://kb.mozillazine.org/Granting_JavaScript_access_to_the_clipboard
				//https://developer.mozilla.org/en/Using_the_Clipboard

				//jAlert("This browser have not enabled support for javascript copy operations.\n\nPlease see: http://kb.mozillazine.org/Granting_JavaScript_access_to_the_clipboard", "Password Crypt");
		   		return 1;
			}

			var clip = Components.classes['@mozilla.org/widget/clipboard;1'].createInstance(Components.interfaces.nsIClipboard);

			if(clip)
			{
				var trans = Components.classes['@mozilla.org/widget/transferable;1'].createInstance(Components.interfaces.nsITransferable);
			
				if(trans)
				{
					var str = new Object();
					var len = new Object();
					var str = Components.classes["@mozilla.org/supports-string;1"].createInstance(Components.interfaces.nsISupportsString);

					if(str)
					{
						var clipid=Components.interfaces.nsIClipboard;
		
						if(clipid)
						{					
							str.data = cliptext;
					
							trans.addDataFlavor('text/unicode');					
							trans.setTransferData("text/unicode", str, cliptext.length*2);		
					
							clip.setData(trans, null, clipid.kGlobalClipboard); // No return value
							return 0;
						}
					}
				}
			}
		}

		//jAlert("This browser does not support any known javascript copy operations.", "Password Crypt");
		return 2;
	}
	catch(err)
	{
		//jAlert('Javascript copy error: ' + err.description, "Password Crypt");
		return 3;
	}
}

/*
function autologin(url, user, password, method) // Not used currently
{

// There may also be another way of doing it with special headers and Basic or Digest Access Authentication (MD5) 
// Basic or Digest Access Authentication reply is 401
// May not bee working across domains with the code below?
// How do I set content (browser) - can I use an IFrame or open in a new window/tab?
// Username and password can be set in the open command (Basic or Digest Access?) or directly in the headers with setRequestHeader and a base64 encoded string (Basic)
// Easy to do from PHP but will reveal username and/or password for server ?????

var http = new XMLHttpRequest();

var url = "get_data.php";
var params = "lorem=ipsum&name=binny";
http.open("GET", url+"?"+params, true);
http.onreadystatechange = function() {//Call a function when the state changes.
	if(http.readyState == 4 && http.status == 200) {
		alert(http.responseText);
	}
}
http.send(null);

or

var url = "get_data.php";
var params = "lorem=ipsum&name=binny";
http.open("POST", url, true);

//Send the proper header information along with the request
http.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
http.setRequestHeader("Content-length", params.length);
http.setRequestHeader("Connection", "close");

http.onreadystatechange = function() {//Call a function when the state changes.
	if(http.readyState == 4 && http.status == 200) {
		alert(http.responseText);
	}
}
http.send(params);

Can be used to set innerHtml = http.responseText

Is it possible to set content of new window ??????



	var murl = url;	
	var pos = strrpos(url, "://");
	if (pos > 0) 
	{ 
		if(password.length)
			murl = substr_replace(url, user + ":" + password + "@", pos+3, 0);
		else
			murl = substr_replace(url, user + "@", pos+3, 0);
	} 
	return murl;     
}
*/



