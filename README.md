# PowerDNS PHP API

This is very simple PHP DNS API for PowerDNS servers. It use directly MySQL-database with PHP-PDO method. 

## Installation

Clone rpository to your server 

```
https://gitlab.truong.fi/internal/PowerDNS-PHP-API.git
```

Configure then to config.php mysql database connection. 

Set to $api_key your own randon generated key. Use this when you authenticate to API. Make sure this is secret!

## Usage

You can easily post to DNS API using example curl. API will automatic create new record if does not exist.

```
https://dns.example.org/api/?key=[api-key]&hostname=$HOSTNAME&type=$TYPE&ttl=300&content=$CONTENT
```
