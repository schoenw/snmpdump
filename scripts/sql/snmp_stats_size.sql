DROP TABLE IF EXISTS snmp_stats_size;
CREATE TABLE snmp_stats_size (
	id bigint unsigned not null auto_increment,

	trace_name varchar(32) not null default '',
	flow_name varchar(64) not null default '',

	op varchar(32) not null default '',
	size int unsigned not null default 0,
	count bigint unsigned not null default 0,

	primary key (id),
	key (trace_name, flow_name)
);
