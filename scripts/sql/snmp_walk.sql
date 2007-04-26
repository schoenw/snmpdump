DROP TABLE IF EXISTS snmp_walk;
CREATE TABLE snmp_walk (
	id bigint unsigned not null auto_increment,
	
	trace_name varchar(32) not null default '',
	flow_name varchar(64) not null default '',

	snmp_version tinyint unsigned not null default 0,
	snmp_operation varchar(32) not null default '',
	err_status int not null default 0,
	err_index int not null default 0,
	non_rep int unsigned not null default 0,
	max_rep int unsigned not null default 0,
	max_rep_changed tinyint unsigned not null default 0,

	start_timestamp double not null default 0,
	end_timestamp double not null default 0,
	duration double not null default 0,
	
	retransmissions int unsigned not null default 0,
	vbc tinyint unsigned not null default 0,
	response_packets int unsigned not null default 0,
	response_oids int unsigned not null default 0,
	response_bytes int unsigned not null default 0,
	request_packets int unsigned not null default 0,
	request_bytes int unsigned not null default 0,

	is_strict tinyint unsigned not null default 0,
	is_prefix_constrained tinyint unsigned not null default 0,
	is_strict_prefix_constr tinyint unsigned not null default 0,

	overshoot int unsigned not null default 0,

	primary key (id),
	key (trace_name, flow_name)
);
