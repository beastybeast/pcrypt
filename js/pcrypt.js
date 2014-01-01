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

function jsonrpc(method, session, dataname, data, id, callback)
{
	var tmpObj = {};
	var tmpArr = [];

	tmpObj.method = method;
	tmpArr[0] = session;
	tmpArr[1] = dataname;
	tmpArr[2] = data;
	tmpObj.params = tmpArr;
	tmpObj.id = id;

	function jsonrpcreply(http)
	{
		if(http.status == 200)
		{
			try 
			{
				 var tmpObjreply = JSON.parse(http.responseText);
				 
				 if(callback)
            callback(tmpObjreply.result, tmpObjreply.error, tmpObjreply.id);
			}
			catch(e)
			{
				if(callback)
					callback('Exception in parsing or callback function error', 'jsonrpc', null);
			}
		}
		else
		{
			if(callback)
			{
        if(typeof(http) == 'object')
          callback('HTTP returned status: ' + http.status, 'http', null);
        else if(typeof(http) == 'string')
          callback('HTTP returned string status: ' + http, 'http', null);
        else
          callback('HTTP returned unknown error,', 'http', null);
      }
		}
	}

	jsoncom('POST', 'https://pcrypt.org/dev/pcrypt.php', JSON.stringify(tmpObj), jsonrpcreply); // POST mean almost unlimited data size
}

function jsoncom(method, url, data, dofunc)
{
  try 
	{
    var http = new XMLHttpRequest(); 

    http.open(method, url, true); 

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
  catch(e)
  {
    dofunc(e.message);
  }
}

function getdata(session, cryptkey, saltcrypt, dataname, id, callback)
{
	function getdatafunc(data, error, id)
	{
		if(error)
		{
			callback(data, error, id);
			return;
		}
		try
		{
			// test crc
			if(crc32(data[0]) != data[1])
			{
				callback('Server checksum is not validated', 'crc', null);
				return;	
			}

			var datastring = decryptstring(cryptkey, saltcrypt, data[0]);
			var lz = new LZ77();
			datastring = lz.decompress(datastring);

			setvalue(dataname, datastring);

			if(datastring.length)
				callback(JSON.parse(datastring), error, id);
			else
				callback(null, error, id); // for some reason JSON.parse fail with empty string	
		}
		catch(e)
		{
			callback('Exception in parsing or decryption', 'data', id);
		}
	}

	try
	{
		if(existvalue(dataname))
		{
			var datastring = getvalue(dataname);

			if(datastring.length)
				callback(JSON.parse(datastring), null, id);
			else
				callback(null, null, id); // for some reason JSON.parse fail with empty string	

			return true;
		}
		else
		{
			jsonrpc('getdata', session, dataname, null, id, getdatafunc);
			return true;
		}
	}
	catch(e)
	{
		return false;
	}	
}

function setdata(session, cryptkey, saltcrypt, dataname, data, id, callback)
{
	try
	{
		var datastring = JSON.stringify(data);
		var lz = new LZ77();
		setvalue(dataname, datastring);
		datastring = lz.compress(datastring);
		datastring = encryptstring(cryptkey, saltcrypt, datastring);
		jsonrpc('setdata', session, dataname, [datastring, crc32(datastring)], id, callback);
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

function setlocalencryption(key, salt)
{
  if(!sessionstorageexist())
    return false;
    
  try
  {
    if(settopname('encryptkey', key))
      return settopname('encryptsalt', salt);
      
    return false; 
  } 
	catch(e)
	{
		return false;
	}
}

function settopname(key, value)
{
  try
  {
    if(top.name.length)
      var tmpObj = JSON.parse(top.name);
    else
      var tmpObj = {};
    
    tmpObj[key] = value;
    
    top.name = JSON.stringify(tmpObj);
    
    return true;
  } 
	catch(e)
	{
		return false;
	}

}

function gettopname(key)
{
  try
  {
    if(!top.name.length)
      return false;

    var tmpObj = JSON.parse(top.name);

    return tmpObj[key];
  } 
	catch(e)
	{
		return false;
	}
}

function setvalue(key, value, encryption)
{
  try
  {
    if(typeof encryption == 'undefined')
      encryption = true;
    
    if(sessionstorageexist())
    {
      var encryptkey = gettopname('encryptkey');
      var encryptsalt = gettopname('encryptsalt');
    
      if(encryptkey && encryptsalt && encryption)
      {      
        sessionStorage[key] = encryptstring(encryptkey, encryptsalt, JSON.stringify(value));
      }
      else
      {
        sessionStorage[key] = JSON.stringify(value);
      }
        
      return true;
    }

    return settopname(key, value);

  } 
	catch(e)
	{
    //alert('debug set false: ' + key);
		return false;
	}
}

function getvalue(key, encryption)
{
  try
  {
    if(typeof encryption == 'undefined')
      encryption = true;
    
    if(sessionstorageexist())
    {
      var encryptkey = gettopname('encryptkey');
      var encryptsalt = gettopname('encryptsalt');
      
      if(encryptkey && encryptsalt && encryption)
      {
        return JSON.parse(decryptstring(encryptkey, encryptsalt, sessionStorage[key]));
      }
      else
      {
        return JSON.parse(sessionStorage[key]);
      }
    }

    return gettopname(key);
    
  } 
	catch(e)
	{
    //alert('debug get false (' + key + '): ' + e.message + ' - ' + sessionStorage[key]);
    return false;
	}
}

function existvalue(key)
{
  try
  {    
    if(sessionstorageexist())
    {		
      return (sessionStorage[key] != undefined);
    }
    
    if(!top.name.length)
      return false;

    var tmpObj = JSON.parse(top.name);

    return (tmpObj[key] == undefined) ?  false : true;
  } 
	catch(e)
	{
		return false;
	}
}

function deletevalue(key)
{
  try
  {
    if(sessionstorageexist())
    {
      delete sessionStorage[key];
      return true;
    }

    if(!top.name.length)
      return false;

    var tmpObj = JSON.parse(top.name);

    delete tmpObj[key];

    top.name = JSON.stringify(tmpObj);
    
    return true;
  } 
	catch(e)
	{
		return false;
	}
}

function flushvalues()
{
	if(sessionstorageexist())
	{
		sessionStorage.clear()
	}
	
	top.name = "";
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

function encryptstring(keycrypt, saltcrypt, text)
{	
	return Aes.Ctr.encrypt(text, Sha256.hash(keycrypt + saltcrypt), 256);
}

function decryptstring(keycrypt, saltcrypt, text)
{		
	return Aes.Ctr.decrypt(text, Sha256.hash(keycrypt + saltcrypt), 256);
}

