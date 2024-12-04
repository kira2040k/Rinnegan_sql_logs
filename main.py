import re
from urllib.parse import unquote
import os
import sys

def decode_comment(line):
    line = line.replace("/**/","")
    line = line.replace("/**/","")
    return line

def remove_whitespace(line):
        line = line.replace("%0b", "")
        return line

def decode_hex_in_url(url):
    

    
    matches = re.findall(r"%[0-9a-fA-F]{2}", url)
    
    
    for match in matches:
        
        decoded_char = bytes.fromhex(match[1:]).decode('utf-8')
        
        url = url.replace(match, decoded_char)
    
    return url


def remove_non_important_comments(input_string):
    
    pattern = r"/\*(?!\!).*?\*/"
    
    cleaned_string = re.sub(pattern, "", input_string, flags=re.DOTALL)
    return cleaned_string

def evaluate_sql_expression(sql):
    
    pattern = r"REVERSE\((.*?)\)"
    
    
    def reverse_match(match):
        
        return match.group(1)[::-1]
    
    
    evaluated_sql = re.sub(pattern, reverse_match, sql, flags=re.IGNORECASE)
    
    
    if '+' in evaluated_sql:
        parts = [part.strip() for part in evaluated_sql.split('+')]
        evaluated_result = ' '.join(parts)  
        return evaluated_result
    
    return evaluated_sql


def parse_concat_function(sql_expression):
    
    pattern = r"CONCAT\((.*?)\)"
    
    match = re.search(pattern, sql_expression, re.IGNORECASE)
    
    if match:
        
        args_str = match.group(1)
        
        
        args = [arg.strip() for arg in args_str.split(',')]
        
        result = ""
        
        
        for arg in args:
            if arg.startswith('0x'):  
                result += bytes.fromhex(arg[2:]).decode('utf-8')
            else:
                result += arg.strip("'")  
        
        
        return result
    else:
        return sql_expression



def parse_concat_function(sql_expression):
    
    pattern = r"CONCAT\((.*?)\)"
    
    def parse_concat(match):
        
        args_str = match.group(1)
        
        
        args = [arg.strip() for arg in args_str.split(',')]
        
        result = ""
        
        
        for arg in args:
            if arg.startswith('0x'):  
                result += bytes.fromhex(arg[2:]).decode('utf-8')
            else:
                result += arg.strip("'")  
        
        return result
    
    
    parsed_sql = re.sub(pattern, parse_concat, sql_expression, flags=re.IGNORECASE)
    
    return parsed_sql

def decode_char_function(query):
    """
    Decodes CHAR() values in an SQL query and replaces them with their string representation.
    
    Args:
        query (str): The SQL query containing CHAR() functions.
        
    Returns:
        str: The modified SQL query with CHAR() values replaced by strings.
    """
    
    char_pattern = re.compile(r"CHAR\(([\d, ]+)\)", re.IGNORECASE)
    
    def char_replacer(match):
        
        numbers = match.group(1).split(',')
        decoded_string = ''.join(chr(int(num.strip())) for num in numbers)
        return f"'{decoded_string}'"  
    
    
    return char_pattern.sub(char_replacer, query)

def decode_hex_in_search(query):
    """
    Processes an SQL query to decode hex values not enclosed in quotes.

    Parameters:
        query (str): The input SQL query.

    Returns:
        str: The modified query with decoded hex values.
    """
    def decode_hex(match):
        hex_value = match.group(0)
        try:
            
            decoded_value = bytes.fromhex(hex_value[2:]).decode('utf-8')
            
            return f"'{decoded_value}'"
        except ValueError:
            raise ValueError(f"Invalid hexadecimal value: {hex_value}")

    
    hex_pattern = r"0x[0-9A-Fa-f]+"

    
    processed_query = re.sub(hex_pattern, decode_hex, query)

    return processed_query

def detect_and_log_system_commands(query, log_file="exec_SQL.txt"):
    """
    Detects system command functions in a SQL query and logs the query if such functions are found.

    Parameters:
        query (str): The SQL query to analyze.
        log_file (str): The file to log detected queries. Defaults to 'exec_SQL.txt'.

    Returns:
        bool: True if a system command was detected and logged, False otherwise.
    """
    dangerous_functions = [
        "sys_exec",       
        "xp_cmdshell",    
        "sp_configure",   
        "OPENROWSET",     
        "COPY FROM PROGRAM", 
        "DBMS_SCHEDULER", 
        "UTL_FILE",       
        "pg_read_file",   
        "pg_write_file",  
        "sys_eval",       
    ]

    pattern = re.compile(r"\b(" + "|".join(dangerous_functions) + r")\b", re.IGNORECASE)

    if pattern.search(query):
        with open(log_file, "a") as file:
            file.write(query + "\n")  
        return True

    return False

def is_folder(path):
    
    if os.path.isfile(path):
        return False
    elif os.path.isdir(path):
        return True
   

def parse_file(input):
    with open(input, "r") as file:
        for line in file:
            if "Query" in line:
                line = line.strip()
                line = decode_comment(line)
                line = remove_whitespace(line)
                line = decode_hex_in_url(line)
                line = remove_non_important_comments(line)
                line = evaluate_sql_expression(line)
                line = parse_concat_function(line)
                line = decode_char_function(line)
                line = decode_hex_in_search(line)
                print(line)

                #this function must execute in the final
                detect_and_log_system_commands(line)




def main():
    if (len(sys.argv) == 1):
        print("python3 main.py <SQL_log_file>")
        sys.exit(2)
    input = sys.argv[1] 
    if(is_folder(input)):
        for root, dirs, files in os.walk(input):
            for file in files:
                parse_file(os.path.join(root, file)) 
    else:
        parse_file(input)


main()