# Rinnegan SQL Logs 📜🔍

Welcome to **Rinnegan SQL Logs**! 🚀 This tool is your ultimate companion for parsing SQL logs, identifying harmful queries, decoding WAF bypasses, and ensuring your database stays secure. 🛡️ Whether you're a security researcher, developer, or just someone curious about SQL, this tool has got you covered! 😎

---

  <img src="./images/logo.jpeg" alt="Rinnegan Logo" width="600">

## Features ✨

- **SQL Logs Parsing** 🗃️  
  Efficiently parse and analyze SQL logs to uncover potential security threats.

- **Harmful Query Detection** 🚨  
  Identify harmful SQL queries containing system commands or malicious intent.

- **WAF Bypass Decoding** 🛡️  
  Decode and understand bypass techniques used to evade Web Application Firewalls.

- **User-Friendly** 🤝  
  Simple and intuitive interface designed for security enthusiasts.

---

## Installation 🛠️

### Requirements 📋
- Python 3.8+ 🐍  
- Required libraries (install via `requirements.txt`)  

### Steps to Install 🏗️
1. Clone the repository:  
   ```bash
   git clone https://github.com/your_username/Rinnegan_sql_logs.git
   cd Rinnegan_sql_logs



### Usage 🕹️


#### Basic Commands 🧙‍♂️

##### Parse file Logs:
```bash
python3 main.py logs.txt
```

##### Parse folder Logs:
```bash
python3 main.py folder
```



### Example Output 🖥️
```SQL
python .\main.py .\file.txt

LSE 0 END),'qqvpq'),NULL,NULL,NULL,NULL,NULL-- -
174 Query    SET NAMES 'utf8mb4' COLLATE 'utf8mb4_general_ci'
174 Query    set autocommit=0
174 Query    SELECT * FROM users WHERE user_id = -5491 UNION ALL SELECT NULL,qqxvq(CASE WHEN (VERSION( LIKE '%MariaDB%') THEN 1 ELSE 0 END),'qqvpq'),NULL,NULL,NULL,NULL,NULL-- -
175 Query    SET NAMES 'utf8mb4' COLLATE 'utf8mb4_general_ci'
175 Query    set autocommit=0
175 Query    SELECT * FROM users WHERE user_id = 1
176 Query    SET NAMES 'utf8mb4' COLLATE 'utf8mb4_general_ci'
176 Query    set autocommit=0
176 Query    SELECT * FROM users WHERE user_id = -2243 UNION ALL SELECT NULL,qqxvqJSON_ARRAYAGG(CONCAT_WS('byqikt'schema_name),'qqvpq'),NULL,NULL,NULL,NULL,NULL FROM INFORMATION_SCHEMA.SCHEMATA-- -
177 Query    SET NAMES 'utf8mb4' COLLATE 'utf8mb4_general_ci'
177 Query    set autocommit=0
177 Query    SELECT * FROM users WHERE user_id = 1 union select 1,2,3--
177 Query    SELECT * FROM users WHERE user_id = 'Bdmin'
177 Query    SELECT *,sys_exec("ls") FROM users WHERE user_id =name='Herp Derper'

```



### Contributing 🤝
We love contributions! 🥳 If you want to improve Rinnegan SQL Logs, feel free to:

- Submit issues 🐛
- Suggest features 💡
- Create pull requests 🛠️

### License 📜
This project is licensed under the MIT License. See the LICENSE file for details.
