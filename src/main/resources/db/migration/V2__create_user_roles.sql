CREATE TABLE user_roles (
  user_role_id INT(11)     NOT NULL AUTO_INCREMENT,
  username     VARCHAR(45) NOT NULL,
  role         VARCHAR(45) NOT NULL,
  PRIMARY KEY (user_role_id),
  UNIQUE KEY uni_username_role (role, username),
  CONSTRAINT fk_user_roles_username FOREIGN KEY (username) REFERENCES users (username)
) ENGINE = InnoDB;
