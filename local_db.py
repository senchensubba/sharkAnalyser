import sqlite3
from typing import List, Tuple, Optional, Any

class LocalDB:
    def __init__(self, db_name: str = 'traffic.db'):
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        print(f"Connected to database: {db_name}")

    def create_table(self, table_sql: str):
        """Takes a CREATE TABLE SQL statement."""
        try:
            self.cursor.execute(table_sql)
            self.conn.commit()
            print(f"Table created or already exists. SQL: {table_sql}")
        except sqlite3.Error as e:
            print(f"Error creating table: {e}")

    def insert(self, query: str, values: Tuple[Any, ...]):
        """Insert a single row into a table."""
        try:
            self.cursor.execute(query, values)
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Insert error: {e}")

    def insert_many(self, query: str, values_list: List[Tuple[Any, ...]]):
        """Insert multiple rows using executemany."""
        try:
            self.cursor.executemany(query, values_list)
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Insert many error: {e}")

    def query(self, query: str, params: Optional[Tuple] = None) -> List[Tuple]:
        """Run a SELECT or general query and return results."""
        try:
            self.cursor.execute(query, params or ())
            return self.cursor.fetchall()
        except sqlite3.Error as e:
            print(f"Query error: {e}")
            return []

    def delete(self, query: str, params: Tuple):
        """Delete rows matching the condition."""
        try:
            self.cursor.execute(query, params)
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Delete error: {e}")

    def close(self):
        """Close the database connection."""
        self.conn.close()
        print("Database connection closed.")
