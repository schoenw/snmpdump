DROP TABLE IF EXISTS snmp_stats_meta;
CREATE TABLE snmp_stats_meta (
	id bigint unsigned not null auto_increment,

	trace_name varchar(32) not null default '',
	flow_name varchar(64) not null default '',

	prop_name varchar(64) not null default '',
	prop_value varchar(128) not null default '',

	primary key (id),
	key (trace_name, flow_name)
);
