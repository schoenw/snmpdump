DROP TABLE IF EXISTS snmp_ip_alias;
CREATE TABLE snmp_ip_alias (
	id int unsigned not null auto_increment,
	trace_name varchar(32) not null default '',
	ip varchar(128) not null default '',
	type char(2) not null default '',
	name varchar(32) not null default '',

	primary key (id),
	key (trace_name, type, ip)
);
