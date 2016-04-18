CREATE TABLE users (
  username VARCHAR(45) NOT NULL,
  password VARCHAR(45) NOT NULL,
  enabled  TINYINT     NOT NULL DEFAULT 1,
  PRIMARY KEY (username)
) ENGINE = InnoDB;