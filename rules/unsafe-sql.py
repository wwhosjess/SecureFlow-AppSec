def examples(db, user_input):
    # ruleid: secureflow.sql-string-construction
    db.execute("SELECT * FROM users WHERE name='" + user_input + "'")
    # ruleid: secureflow.sql-string-construction
    db.execute(f"SELECT * FROM users WHERE name='{user_input}'")
    # ruleid: secureflow.sql-string-construction
    query = "SELECT * FROM users WHERE name='" + user_input + "'"
    db.execute(query)
    # ok: secureflow.sql-string-construction
    db.execute("SELECT * FROM users WHERE name=?", (user_input,))
    # ok: secureflow.sql-string-construction
    db.execute("SELECT id, name FROM products WHERE public=1")
