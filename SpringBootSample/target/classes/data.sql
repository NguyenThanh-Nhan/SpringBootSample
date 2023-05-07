--insert into employee (id, name, age) values('1','Nguyen Van A',30);
--insert into employee (id, name, age) values('2','Nguyen Van B',24);
--insert into employee (id, name, age) values('3','Nguyen Van C',27);
--
--/* User master */
--INSERT INTO m_user (user_id, password, user_name, birthday, age, gender, department_id, role)
--VALUES
--('system@co.jp', 'password', 'System Administrator', '2000-01-01', 21, 1, 1, 'ROLE_ADMIN'), 
--('user@co.jp', 'password', 'User1', '2000-01-01', 21, 2, 2, 'ROLE_GENERAL');
--/* Department master */
--INSERT INTO m_department (department_id, department_name)
--VALUES
--(1, 'System Management'),
--(2, 'Sales');
--/* Salary table */
--INSERT INTO t_salary (user_id, year_month, salary)
--VALUES
--('user@co.jp', '11/2020', 2800), 
--('user@co.jp', '12/2020', 2900), 
--('user@co.jp', '01/2021', 3000);

INSERT INTO employee (id, name, age)
VALUES('1', 'Tom', 30);

/* User master */
INSERT INTO m_user (user_id, password, user_name, birthday, age, gender, department_id, role) 
VALUES
	('system@co.jp', '$2a$10$5Z9lmxfHY5zkR/9y8glYcuYmp8N0MRHlpTEfZc2KGOsJoUfzGap9u', 'System Administrator', '2000-01-01', 21, 1, 1, 'ROLE_ADMIN')
	, ('user@co.jp', '$2a$10$5Z9lmxfHY5zkR/9y8glYcuYmp8N0MRHlpTEfZc2KGOsJoUfzGap9u', 'User1', '2000-01-01', 21, 2, 2, 'ROLE_GENERAL');

/* Department master */
INSERT INTO m_department (department_id, department_name) 
VALUES
	(1, 'System Management')
	,(2, 'Sales');

/* Salary table */
INSERT INTO t_salary (user_id, year_month, salary) 
VALUES
	('user@co.jp', '11/2020', 2800)
	, ('user@co.jp', '12/2020', 2900)
	, ('user@co.jp', '01/2021', 3000)
	;