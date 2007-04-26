DROP TABLE IF EXISTS snmp_meta;
CREATE TABLE snmp_meta (
	id bigint unsigned not null auto_increment,

	trace_name varchar(32) not null default '',
	flow_name varchar(64) not null default '',

	start_timestamp double not null default 0,
	end_timestamp double not null default 0,
	messages bigint unsigned not null default 0,
	managers int unsigned not null default 0,
	agents int unsigned not null default 0,
	unknown int unsigned not null default 0,

	primary key (id),
	key (trace_name, flow_name)
);
