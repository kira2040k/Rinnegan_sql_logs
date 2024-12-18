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

---

## Installation 🛠️

### Requirements 📋
- Python  🐍  

### Steps to Install 🏗️
1. Clone the repository:  
   ```bash
   git clone https://github.com/kira2040k/Rinnegan_sql_logs.git
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



## Example Output 🖥️

### SQL Query Parsing Examples

| **Original Query**                                                                 | **Parsed Query**                                                            |
|------------------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| `SELECT * FROM users WHERE user_id = 1 un/**/ion se/**/lect 1,2,3--`               | `SELECT * FROM users WHERE user_id = 1 union select 1,2,3--`                |
| `SELECT * FROM users WHERE user_id = CHAR(66,100,109,105,110)`                     | `SELECT * FROM users WHERE user_id = 'Bdmin'`                               |
| `SELECT *,sys_exec("ls") FROM users WHERE user_id =name=0x4865727020446572706572` | `SELECT *,sys_exec("ls") FROM users WHERE user_id =name='Herp Derper'`      |




### Contributing 🤝
We love contributions! 🥳 If you want to improve Rinnegan SQL Logs, feel free to:

- Submit issues 🐛
- Suggest features 💡
- Create pull requests 🛠️

### License 📜
This project is licensed under the MIT License. See the LICENSE file for details.
