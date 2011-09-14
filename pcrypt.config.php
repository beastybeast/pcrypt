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

############################################################### 
#
#The database engine support the following databases (not tested with anything other than mysql):
#
# Databasetype	Database Name
# fbsq 		Frontbase
# gladius	Flat File (text file)
# maxdb 	Max DB
# msql 		Mini SQL
# mssql 	Microsoft SQL
# mysql 	MySql
# mysqli 	MySql Improved
# mysqlt 	MySql w/transactions
# postgres 	PostGres
# postgres64 	PostGres 6.4
# postgres7 	PostGres 7
# postgres8 	Postgres 8
# sqlite 	SqLite
# sqlitepo 	SqLite Pro
# sybase 	Sybase
# sybase_ase 	SyBase ASE 
#
# This can be specified in variable $db_system 
#
# Please make sure that the path /dev/urandom is accessable on linux systems
# 
###############################################################

$db_system = "mysql"; // see above
$db_server = "localhost"; // IP adr. of where database is located
$db_user = "passwords"; // database user name. 
$db_password = "641677216150a2f1"; // database password
$db_database = "passwordcrypt"; // name of database

?>
