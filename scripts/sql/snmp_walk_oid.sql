DROP TABLE IF EXISTS snmp_walk_oid;
CREATE TABLE snmp_walk_oid (
	id bigint unsigned not null auto_increment,
	walk_id bigint unsigned not null default 0,

	oid varchar(64) not null default '',

	primary key (id),
	key (walk_id)
);
