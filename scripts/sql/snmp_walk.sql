CREATE TABLE snmp_walk (
	id bigint unsigned not null auto_increment,
	
	source_file varchar(128) not null default '',
	file_pos int unsigned not null default 0,
	flow_str varchar(128) not null default '',

	g_ip varchar(128) not null default '',
	g_port int unsigned not null default 0,
	r_ip varchar(128) not null default '',
	r_port int unsigned not null default 0,

	snmp_version tinyint unsigned not null default 0,
	snmp_operation varchar(32) not null default '',
	err_status int not null default 0,
	err_index int not null default 0,
	non_rep int unsigned not null default 0,
	max_rep int unsigned not null default 0,

	start_timestamp double not null default 0,
	end_timestamp double not null default 0,
	duration double not null default 0,
	
	packets int unsigned not null default 0,
	retransmissions int unsigned not null default 0,
	vbc tinyint unsigned not null default 0,
	retrieved_oids int unsigned not null default 0,
	retrieved_bytes int unsigned not null default 0,
	sent_bytes int unsigned not null default 0,

	is_strict tinyint unsigned not null default 0,
	is_prefix_constrained tinyint unsigned not null default 0,
	broken_prefix_pos int unsigned not null default 0,

	primary key (id),
	key (source_file)
);
