<?php
# Poweradmin DNS Update API

include "config.php";

function connect_mysql_pdns() {
	include "config.php";

try {
        $conn = new PDO( "mysql:host=$dbserverpdns;dbname=$dbnamepdns", $dbuserpdns, $dbpasspdns);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $conn->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);} catch (PDOException $e) {
}
catch(PDOException $e)
    {
    die ("ERROR: " . $e->getMessage());
    }
return $conn;
}

function check_records_pdns($hostname, $type) {
        $conn = connect_mysql_pdns();
        $sql = $conn->prepare ("SELECT content FROM records WHERE name = ? AND type = ? AND disabled=0");
        $sql -> execute([$hostname, $type]);
        $result = $sql->fetch(PDO::FETCH_ASSOC);
        if($sql->rowCount() > 0) {
                return $result['content'];
        }
        else {
                return false;
        }

}

//Get record id from powerdns database
function get_record_ids_pdns($name, $content, $type) {
        $conn = connect_mysql_pdns();
        $sql = $conn->prepare ("SELECT id FROM records WHERE name = ? AND content = ? AND type = ?");
        $sql -> execute([$name, $content, $type]);
        $result = $sql->fetch(PDO::FETCH_ASSOC);
        if($sql->rowCount() > 0) {
                return $result['id'];
        }
        else {
                return false;
        }
}

//Get domain_id from powerdns database
function get_domain_ids_pdns($domain) {
        $conn = connect_mysql_pdns();
        $sql = $conn->prepare ("SELECT id FROM domains WHERE name = ?");
        $sql -> execute([$domain]);
        $result = $sql->fetch(PDO::FETCH_ASSOC);
        if($sql->rowCount() > 0) {
                return $result['id'];
        }
        else {
                return false;
        }
}
//Add DNS-record to database
function do_add($domain_id, $name, $content, $type, $ttl) {
        $conn = connect_mysql_pdns();

        $prio = "0";
        $date = time();

        $sql = $conn->prepare ("INSERT INTO records (domain_id, name, type, content, ttl, prio, change_date) VALUES (?, ?, ?, ?, ?, ?, ?)");
        if ($sql -> execute([$domain_id, $name, $type, $content, $ttl, $prio, $date])) {
                return true;
        }
        else {
                return false;
        }

}

//Update DNS-record to database
function do_update($hostname, $content, $type) {
        $conn = connect_mysql_pdns();
        $sql = $conn->prepare ("UPDATE records SET content=? WHERE name=? AND type=?");
        if ($sql -> execute([$content, $hostname, $type])) {
                return true;
        }
        else {
                return false;
        }
}


//Update SOA to DNS-server
function do_update_soa($hostname, $type) {
	$conn = connect_mysql_pdns();
	$sql = $conn->prepare ("SELECT domain_id FROM records WHERE name = ? AND type= ? AND disabled=0 LIMIT 1");
	$sql -> execute([$hostname, $type]);
	$result = $sql->fetch(PDO::FETCH_ASSOC);
	if($sql->rowCount() > 0) {
		$sql = $conn->prepare ("SELECT name FROM domains WHERE id=?");
		$sql -> execute([$result['domain_id']]);
		$result = $sql->fetch(PDO::FETCH_ASSOC);
		$domain = $result['name'];
		if($sql->rowCount() > 0) {
			$type = "SOA";
			$sql = $conn->prepare ("SELECT content FROM records WHERE name=? AND type=? AND disabled=0");
			$sql -> execute([$domain, $type]);
			$result = $sql->fetch(PDO::FETCH_ASSOC);
			if($sql->rowCount() > 0) {
				preg_match('/([^\s]+) ([^\s]+) (\d+) (\d+) (\d+) (\d+) (\d+)/', $result['content'], $match);
				$soa = sprintf('%s %s %d %d %d %d %d', $match[1], $match[2], $match[3]+1, $match[4], $match[5], $match[6], $match[7]);
				$sql = $conn->prepare("UPDATE records SET content=? WHERE name=? AND type=?");
				if ($sql -> execute([$soa, $domain, $type])) {
					return true;
				}
				else {
					return false;
				}
				
			}
			else {
				return false;
			}
		}
		else {
			return false;
		}
	}
	else {
		return false;
	}
}

if (empty($_GET['key'])) {
        die("Unauthorized");
}
if ($_GET['key'] !== $api_key) {
        die("Unauthorized");
}

$hostname = $_GET['hostname'];
if(!$hostname)
        $hostname = $_SERVER['QUERY_STRING'];
$hostname = trim($hostname);

$content = $_GET['content'];
if(!$content)
        $content = $_SERVER['QUERY_STRING'];
$content = trim($content);

$type = $_GET['type'];
if(!$type)
        $type = $_SERVER['QUERY_STRING'];
$type = trim($type);
$type = strtoupper($type);

$ttl = $_GET['ttl'];
if(!$ttl)
        $ttl = $_SERVER['QUERY_STRING'];
$ttl = trim($ttl);

//Set default TTL
if (isset($ttl)) {
        $ttl = "300";
}

//Check allowed records type
if (!in_array($type, array("TXT", "TLSA"))) {
        print "dnserr - please specify record type TXT or TLSA";
        exit();
}


if ($type == "A" || $type == "AAAA") {
	$ip = $content;
	if (!$ip || (!filter_var($ip, FILTER_VALIDATE_IP))) {
		if (isset($_SERVER['HTTP_INCAP_CLIENT_IP'])) {
			$ip = $_SERVER['HTTP_INCAP_CLIENT_IP'];
		} else if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
			$ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
		} else {
			$ip = $_SERVER['REMOTE_ADDR'];
		}
	}
	
	
}

$domain = explode('.',$hostname);
$domain = array_reverse($domain);
$domain = $domain[1].'.'.$domain[0];

$check_records_pdns = check_records_pdns($hostname, $type);
if ($check_records_pdns == false) {
        $domain_id = get_domain_ids_pdns($domain);


        $do_add = do_add($domain_id, $hostname, $content, $type, $ttl);
        if ($do_add == true) {
                //Update SOA records on hostname
                if(do_update_soa($hostname, $type) == false) {
                        print "dnserr - soa update failed";
                        exit();
                }
                $get_record_ids_pdns = get_record_ids_pdns($hostname, $content, $type);
                print "good - ID: ". $get_record_ids_pdns;
        }
        else {
                print "Something wrong adding record to DNS.";
                        exit();
        }
}

else {
        //If DNS record already available, then do update
        $do_update = do_update($hostname, $content, $type);
        if ($do_update == true) {
        //Update SOA records on hostname
                if(do_update_soa($hostname, $type) == false) {
                        print "dnserr - soa update failed";
                        exit();
                }
                $get_record_ids_pdns = get_record_ids_pdns($hostname, $content, $type);
                        print "good - ID: ". $get_record_ids_pdns;
                }
        }

?>

