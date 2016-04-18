CREATE TABLE authorities (
  id INT(11)     NOT NULL AUTO_INCREMENT,
  username     VARCHAR(45) NOT NULL,
  authority         VARCHAR(45) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uk_authorities (authority, username),
  CONSTRAINT fk_authorities_username FOREIGN KEY (username) REFERENCES users (username)
) ENGINE = InnoDB;
