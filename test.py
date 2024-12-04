import re

def detect_and_log_system_commands(query, log_file="exec_SQL.txt"):
    """
    Detects system command functions in a SQL query and logs the query if such functions are found.

    Parameters:
        query (str): The SQL query to analyze.
        log_file (str): The file to log detected queries. Defaults to 'exec_SQL.txt'.

    Returns:
        bool: True if a system command was detected and logged, False otherwise.
    """
    # List of dangerous SQL functions that can execute system commands
    dangerous_functions = [
        "sys_exec",       # MySQL
        "xp_cmdshell",    # MSSQL
        "sp_configure",   # MSSQL
        "OPENROWSET",     # MSSQL
        "COPY FROM PROGRAM", # PostgreSQL
        "DBMS_SCHEDULER", # Oracle
        "UTL_FILE",       # Oracle
        "pg_read_file",   # PostgreSQL
        "pg_write_file",  # PostgreSQL
        "sys_eval",       # MariaDB
    ]

    # Build a regex pattern to search for these functions
    pattern = re.compile(r"\b(" + "|".join(dangerous_functions) + r")\b", re.IGNORECASE)

    # Check if the query contains any of the dangerous functions
    if pattern.search(query):
        with open(log_file, "a") as file:
            file.write(query + "\n")  # Append the query to the file
        return True

    return False

# Example Usage
query = "SELECT * FROM users WHERE name = sys_exec('ls');"
if detect_and_log_system_commands(query):
    print("System command detected and logged.")
else:
    print("No dangerous commands detected.")
