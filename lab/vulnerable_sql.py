def search(db, term):
    query = "SELECT id, name FROM products WHERE public = 1 AND name LIKE '%" + term + "%'"
    return db.execute(query).fetchall()
