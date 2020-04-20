CREATE TABLE user_org (
  user_id SERIAL PRIMARY KEY NOT NULL,
  orgs          JSONB              NOT NULL,
  creation_time timestamp default CURRENT_TIMESTAMP,
  update_time   timestamp default CURRENT_TIMESTAMP
);

DO $$
BEGIN
    IF exists(select * from properties where k = 'auth_mode') THEN
        update properties set v='dashboard' where k = 'auth_mode';
    ELSE
        insert into properties (k, v) values ('auth_mode', 'dashboard');
    END IF;
END $$;
