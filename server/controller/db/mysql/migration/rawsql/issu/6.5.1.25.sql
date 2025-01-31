DROP PROCEDURE IF EXISTS AddColumnAndSetIfNotExists;

CREATE PROCEDURE AddColumnAndSetIfNotExists(
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255),
    IN colType VARCHAR(255),
    IN defaultVal VARCHAR(255),
    IN afterCol VARCHAR(255)
)
BEGIN
    DECLARE col_count INT;

    -- check whether the column exists, pay attention to specify the @tableSchema variable which will be added when this file is executed
    SELECT COUNT(*)
    INTO col_count
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = tableName
    AND COLUMN_NAME = colName;

    -- if the column does not exist, add the column
    IF col_count = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD COLUMN ', colName, ' ', colType, ' DEFAULT ', defaultVal, ' AFTER ', afterCol);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL AddColumnAndSetIfNotExists('alarm_policy', 'team_id', 'INTEGER', '1', 'id');
CALL AddColumnAndSetIfNotExists('alarm_endpoint', 'team_id', 'INTEGER', '1', 'id');

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.25';
-- modify end
