create table user_org (
  user_id SERIAL PRIMARY KEY NOT NULL,
  orgs          JSONB              NOT NULL,
  creation_time timestamp default CURRENT_TIMESTAMP,
  update_time   timestamp default CURRENT_TIMESTAMP
);

if exists(select * from properties where k = 'auth_mode') then
    update properties set v='dashboard' where k = 'auth_mode';
else
    insert into properties (k, v) values 
    ('auth_mode', 'dashboard');
end if