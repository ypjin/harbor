CREATE TABLE user_org (
  user_id SERIAL PRIMARY KEY NOT NULL,
  orgs          JSONB              NOT NULL,
  creation_time timestamp default CURRENT_TIMESTAMP,
  update_time   timestamp default CURRENT_TIMESTAMP
);

DO $$
BEGIN
    IF exists(select * from properties where k = 'auth_mode') THEN
        update properties set v='ars_auth' where k = 'auth_mode';
    ELSE
        insert into properties (k, v) values ('auth_mode', 'ars_auth');
    END IF;

    IF exists(select * from properties where k = 'robot_token_duration') THEN
        update properties set v='131400000' where k = 'robot_token_duration';
    ELSE
        insert into properties (k, v) values ('robot_token_duration', '131400000');
    END IF;
END $$;
