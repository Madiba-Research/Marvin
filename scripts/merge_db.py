import sys
import sqlite3

# from custom_define import TABLE_NETWORK, TABLE_PASSTHROUGH, TABLE_TRAFFIC_SEPARATION, TABLE_VALIDATION, TABLE_ATTRIBUTION
from custom_define import CREATE_TABLE_SQLS, TABLE_PARAMS_DICTS


dest_db = sys.argv[1]
subdb_lists = sys.argv[2: ]

print("destination database: ", dest_db)
print("sub database list: ", subdb_lists)


def attach_databases():
    conn = sqlite3.connect(dest_db)
    cursor = conn.cursor()
    for src_db in subdb_lists:
        print(f"---- Start to merge databse: {src_db} ---- ")
        attach_sql = f"ATTACH '{src_db}' AS 'db_{src_db}'"
        print(attach_sql)
        cursor.execute(attach_sql)
        conn.commit()

        # create tables
        for t in CREATE_TABLE_SQLS:
            sql = CREATE_TABLE_SQLS[t]
            print(sql)
            cursor.execute(sql)
            conn.commit()

        # insert values
        for t in TABLE_PARAMS_DICTS:
            params = TABLE_PARAMS_DICTS[t]
            insert_sql = f"INSERT INTO {t} ({params}) SELECT {params} FROM 'db_{src_db}'.{t}"
            print(insert_sql)
            cursor.execute(insert_sql)
            conn.commit()


if __name__ == "__main__":
    attach_databases()
