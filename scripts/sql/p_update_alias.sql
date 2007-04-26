CREATE DEFINER=`ciocov`@`localhost` PROCEDURE `p_update_alias`()
BEGIN
        DECLARE done INT DEFAULT 0;
        DECLARE c INT DEFAULT 0;
        DECLARE tr_name VARCHAR(32);
        DECLARE ip_addr VARCHAR(128);
        DECLARE cur1 CURSOR FOR SELECT DISTINCT t1.trace_name, t1.cg_ip FROM snmp_walk AS t1 WHERE NOT EXISTS (SELECT * FROM snmp_ip_alias AS t2 WHERE t2.trace_name = t1.trace_name AND t2.type = 'cg' AND t2.ip = t1.cg_ip);
        DECLARE cur2 CURSOR FOR SELECT DISTINCT t1.trace_name, t1.cr_ip FROM snmp_walk AS t1 WHERE NOT EXISTS (SELECT * FROM snmp_ip_alias AS t2 WHERE t2.trace_name = t1.trace_name AND t2.type = 'cr' AND t2.ip = t1.cr_ip);
        DECLARE CONTINUE HANDLER FOR SQLSTATE '02000' SET done = 1;
        OPEN cur1;
        OPEN cur2;
        REPEAT
                FETCH cur1 INTO tr_name, ip_addr;
                IF NOT done THEN
                        SELECT count(*) INTO c FROM snmp_ip_alias WHERE trace_name = tr_name AND type = 'cg';
                        INSERT INTO snmp_ip_alias (trace_name, ip, type, name) VALUES (tr_name, ip_addr, 'cg', CONCAT('m', c));
                END IF;
        UNTIL done END REPEAT;
        SET done = 0;
        REPEAT
                FETCH cur2 INTO tr_name, ip_addr;
                IF NOT done THEN
                        SELECT count(*) INTO c FROM snmp_ip_alias WHERE trace_name = tr_name AND type = 'cr';
                        INSERT INTO snmp_ip_alias (trace_name, ip, type, name) VALUES (tr_name, ip_addr, 'cr', CONCAT('a', c));
                END IF;
        UNTIL done END REPEAT;
        CLOSE cur1;
        CLOSE cur2;
END
